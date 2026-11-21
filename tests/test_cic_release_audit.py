"""Synthetic fixtures for the read-only corrected CIC-IDS2017 audit."""

import csv
import io
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from zipfile import BadZipFile, ZipFile

from ml.audit_cic_release import (
    DAYS, DATES, REQUIRED_COLUMNS, audit_archive, label_policy, timestamp_value, tuple_key,
)


class CicReleaseAuditTests(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name) / "synthetic.zip"
        self.columns = sorted(REQUIRED_COLUMNS | {"Flow Bytes/s"})

    def row(self, day, **updates):
        fields = dict.fromkeys(self.columns, "0")
        fields.update({
            "Timestamp": f"{DATES[day]} 01:02:03.000004",
            "Label": "BENIGN", "Attempted Category": "-1",
            "Src IP": "192.0.2.1", "Dst IP": "198.51.100.1",
            "Src Port": "12345", "Dst Port": "443", "Protocol": "6",
            "Flow ID": "192.0.2.1-198.51.100.1-12345-443-6",
            "Total Fwd Packet": "2", "Flow Duration": "100",
        })
        fields.update(updates)
        return fields

    def write_zip(self, overrides=None, *, extra_member=False):
        overrides = overrides or {}
        with ZipFile(self.path, "w") as archive:
            for day, name in enumerate(DAYS):
                handle = io.StringIO(newline="")
                writer = csv.DictWriter(handle, fieldnames=self.columns, lineterminator="\n")
                writer.writeheader()
                writer.writerows(overrides.get(day, [self.row(day)]))
                archive.writestr(f"{name.lower()}.csv", handle.getvalue())
            if extra_member:
                archive.writestr("unexpected.csv", "placeholder")

    def test_archive_audit_counts_raw_duplicates_and_same_vectors_across_boundaries(self):
        flow = self.row(4, Label="DDoS")
        self.write_zip({4: [flow, {**flow, "id": "1"}]})
        original = self.path.read_bytes()
        report = audit_archive(self.path)
        self.assertTrue(report["crc_verified"])
        self.assertEqual(self.path.read_bytes(), original)
        self.assertEqual(list(self.path.parent.iterdir()), [self.path])
        self.assertEqual(report["groups"]["raw_excluding_id"]["duplicate_occurrences"], 1)
        native = report["groups"]["native"]
        self.assertEqual(native["distinct_groups"], 1)
        self.assertEqual(native["conflicting_rows"], 6)
        shared = native["boundaries"]["fit and calibration to validation"]
        self.assertEqual((shared["shared_groups"], shared["left_benign"], shared["right_attacks"]), (1, 3, 2))

    def test_profiles_invalid_values_and_preserves_published_labels(self):
        flow = self.row(1, **{
            "Label": "Attempted attack", "Attempted Category": "Example",
            "Flow Duration": "-1", "Flow Bytes/s": "Infinity",
            "Timestamp": "invalid",
        })
        self.write_zip({1: [flow]})
        report = audit_archive(self.path)["members"]["Tuesday"]
        self.assertEqual(report["raw_labels"], {"Attempted attack": 1})
        self.assertEqual(report["policy_counts"], {0: 1})
        self.assertEqual(report["native_eligible"], {})
        self.assertEqual(report["issues"]["invalid_native_counters"], 1)
        self.assertEqual(report["issues"]["invalid_timestamp"], 1)
        self.assertEqual(report["column_quality"]["Flow Bytes/s"]["counts"], {"nonfinite": 1})

    def test_rejects_archive_with_extra_member(self):
        self.write_zip(extra_member=True)
        with self.assertRaisesRegex(ValueError, "exactly the five"):
            audit_archive(self.path)

    def test_crc_failure_is_detected(self):
        self.write_zip()
        contents = self.path.read_bytes()
        self.path.write_bytes(contents.replace(b"2017-07-03 01:02:03", b"2017-07-03 01:02:04", 1))
        with self.assertRaises(BadZipFile):
            audit_archive(self.path)

    def test_tuple_pairs_and_naive_clock(self):
        first = tuple_key("192.0.2.1", "12345", "198.51.100.1", "443", 6)
        reverse = tuple_key("198.51.100.1", "443", "192.0.2.1", "12345", 6)
        self.assertEqual(first, reverse)
        self.assertNotEqual(first, tuple_key("198.51.100.1", "12345", "192.0.2.1", "443", 6))
        self.assertIsNone(timestamp_value("2017-07-03 01:02:03.123456").tzinfo)
        with self.assertRaises(ValueError):
            timestamp_value("2017-07-03 01:02:03+00:00")
        self.assertEqual(label_policy("DoS", "-1"), (1, False))
        self.assertEqual(label_policy("DoS", "Attempted"), (0, True))
