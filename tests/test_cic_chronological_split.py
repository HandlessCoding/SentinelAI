"""Synthetic release tests for the chronology and overlap decisions."""

import csv
import gzip
import io
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from zipfile import ZipFile

from ml.audit_cic_release import DATES, DAYS, REQUIRED_COLUMNS
from ml.cic_chronological_split import (
    BITS, PRIMARY, ROW_MANIFEST, audit_split, digest, feasibility,
)


class CicChronologicalSplitTests(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name) / "synthetic.zip"
        self.output = self.path.parent / "output"
        self.columns = sorted(REQUIRED_COLUMNS)

    def row(self, day, *, duration, port, flow_id, **updates):
        fields = dict.fromkeys(self.columns, "0")
        fields.update({
            "Timestamp": f"{DATES[day]} 11:12:13.000014",
            "Label": "BENIGN", "Attempted Category": "-1",
            "Src IP": "192.0.2.1", "Dst IP": "198.51.100.1", "Src Port": str(port),
            "Dst Port": "443", "Protocol": "6", "Flow ID": flow_id,
            "Total Fwd Packet": "2", "Total Bwd packets": "1",
            "Flow Duration": str(duration),
            "Total Length of Fwd Packet": "20", "Total Length of Bwd Packet": "30",
        })
        fields.update(updates)
        return fields

    def write_zip(self, overrides=None, *, flip_labels=False):
        members = [
            [self.row(0, duration=100, port=1111, flow_id="flow-a")],
            [self.row(1, duration=100, port=1111, flow_id="flow-a", Label="Fit")],
            [self.row(2, duration=200, port=2222, flow_id="flow-b")],
            [
                self.row(3, duration=100, port=3333, flow_id="flow-c", Label="Thursday"),
                self.row(3, duration=300, port=4444, flow_id="flow-d"),
            ],
            [
                self.row(4, duration=500, port=3333, flow_id="flow-c", Label="Friday"),
                self.row(4, duration=600, port=443, flow_id="flow-e", **{
                    "Src IP": "198.51.100.1", "Dst IP": "192.0.2.1", "Dst Port": "4444",
                }),
                self.row(4, duration=100, port=7777, flow_id="flow-f", **{
                    "Total Length of Fwd Packet": "21",
                }),
                self.row(4, duration=700, port=8888, flow_id="flow-a"),
            ],
        ]
        for day, updates in (overrides or {}).items():
            members[day][0].update(updates)
        with ZipFile(self.path, "w") as zip_file:
            for day, (name, records) in enumerate(zip(DAYS, members, strict=True)):
                buffer = io.StringIO(newline="")
                writer = csv.DictWriter(buffer, fieldnames=self.columns, lineterminator="\n")
                writer.writeheader()
                for ordinal, record in enumerate(records, 1):
                    record["id"] = str(ordinal)
                    if flip_labels:
                        record["Label"] = "Synthetic attack" if record["Label"] == "BENIGN" else "BENIGN"
                    writer.writerow(record)
                zip_file.writestr(f"{name.lower()}.csv", buffer.getvalue())

    def audit(self, *, expected=None):
        return audit_split(self.path, self.output, expected_sha256=expected or digest(self.path),
                           progress=lambda message: None, chunk_bytes=512)

    def manifest_rows(self, member):
        with gzip.open(self.output / ROW_MANIFEST, "rt", encoding="utf-8", newline="") as stream:
            columns = ("primary_eligible", "source_overlap_bits", "primary_overlap_bits")
            return [tuple(int(row[col]) for col in columns) for row in csv.DictReader(stream)
                    if row["member"] == member]

    def test_union_and_retained_history_are_chronological(self):
        self.write_zip()
        archive_digest = digest(self.path)
        report = self.audit()
        self.assertEqual(digest(self.path), archive_digest)
        self.assertEqual(self.manifest_rows("monday.csv"), [(0, 15, 15)])
        self.assertEqual(self.manifest_rows("tuesday.csv"), [(1, 0, 0)])
        self.assertEqual(self.manifest_rows("thursday.csv"), [(0, 3, 3), (1, 0, 0)])
        self.assertEqual(self.manifest_rows("friday.csv"), [
            (1, BITS["tuple"] | BITS["flow_id"], 0), (0, BITS["tuple"], BITS["tuple"]),
            (0, BITS["portable"], BITS["portable"]), (0, BITS["flow_id"], BITS["flow_id"]),
        ])
        self.assertEqual(report["cohorts"][PRIMARY]["validation"]["attack_categories"], {"Friday": 1})
        overlaps = report["overlapping_groups"]
        self.assertEqual(overlaps["unfiltered"]["fit_to_validation"]["portable"], 1)
        self.assertEqual(overlaps["both_vectors"]["calibration_to_validation"]["tuple"], 1)
        self.assertTrue(all(not n for pair in overlaps[PRIMARY].values() for n in pair.values()))
        self.assertFalse(report["training_allowed"])
        self.assertEqual(report["row_manifest"]["sha256"], digest(self.output / ROW_MANIFEST))

    def test_labels_only_change_support_reports(self):
        self.write_zip()
        first = self.audit()
        self.write_zip(flip_labels=True)
        second = self.audit()
        self.assertNotEqual(first["cohorts"], second["cohorts"])
        self.assertEqual(first["overlapping_groups"], second["overlapping_groups"])
        self.assertEqual(first["row_manifest"], second["row_manifest"])

    def test_invalid_predictor_or_capture_day_fails_closed(self):
        for changes in ({"Flow Duration": "NaN"}, {"Timestamp": f"{DATES[0]} 01:00:00"}):
            with self.subTest(changes=changes):
                self.write_zip({1: changes})
                with self.assertRaisesRegex(ValueError, "Tuesday record 1"):
                    self.audit()
                self.assertEqual(list(self.output.iterdir()), [])

    def test_rejects_unverified_archive_before_audit(self):
        self.write_zip()
        with self.assertRaisesRegex(ValueError, "Source SHA-256"):
            self.audit(expected="wrong")
        self.assertEqual(list(self.output.iterdir()), [])

    def test_feasibility_rejects_support_failure_or_overlap(self):
        cohorts = {
            "unfiltered": {"fit": {"benign": 20_000, "attack": 20_000,
                                   "attack_categories": {"scan": 100, "rare": 99}}},
            PRIMARY: {"fit": {"benign": 10_000, "attack": 10_000,
                              "attack_categories": {"scan": 50}}},
        }
        groups = {PRIMARY: {"fit_to_validation": {"portable": 0}}}
        self.assertEqual(feasibility(cohorts, groups), [])
        cohorts[PRIMARY]["fit"]["attack_categories"]["scan"] = 49
        cohorts[PRIMARY]["fit"]["benign"] = 9_999
        groups[PRIMARY]["fit_to_validation"]["portable"] = 1
        self.assertEqual(feasibility(cohorts, groups), [
            {"boundary": "fit_to_validation", "key": "portable", "overlapping_groups": 1},
            {"role": "fit", "class": "benign", "source": 20_000, "kept": 9_999},
            {"role": "fit", "category": "scan", "source": 100, "kept": 49},
        ])
