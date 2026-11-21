"""Exercise the G14 read-only audit with small, synthetic CSVs."""

import csv
from hashlib import sha256
from os import utime
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from ml.audit_level2_data import PUBLISHED_COLUMNS, audit_dataset, raw_row_key
from ml.level2_flow_schema import SOURCE_COLUMNS


class AuditLevel2DataTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.folder = Path(temporary.name)
        self.path = self.folder / "synthetic.csv"
        self.benign = dict.fromkeys(PUBLISHED_COLUMNS, "0")
        self.benign.update(
            IPV4_SRC_ADDR="192.0.2.10", IPV4_DST_ADDR="198.51.100.2",
            PROTOCOL="6", FLOW_DURATION_MILLISECONDS="30", IN_PKTS="2", IN_BYTES="100",
            Attack="Benign",
        )

    def write_csv(self, rows, columns=PUBLISHED_COLUMNS):
        with self.path.open("w", encoding="utf-8", newline="") as file:
            writer = csv.DictWriter(file, fieldnames=columns)
            writer.writeheader()
            writer.writerows(rows)

    def test_full_row_duplicates_and_conflicting_vectors_span_chunks(self):
        other = {**self.benign, "IN_BYTES": "42", "Label": "1", "Attack": "DoS"}
        conflict = {**self.benign, "IN_BYTES": "100.0", "Label": "1", "Attack": "XSS"}
        self.write_csv([self.benign, other, conflict, self.benign])
        before = self.path.read_bytes()
        with patch("ml.audit_level2_data.RECORDS_PER_CHUNK", 2):
            report = audit_dataset(self.path, chunk_bytes=420)
        self.assertEqual(report["sha256"], sha256(before).hexdigest())
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(list(self.folder.iterdir()), [self.path])
        self.assertEqual(report["records"], 4)
        self.assertEqual(report["binary_classes"], {"benign": 2, "attack": 2})
        self.assertEqual(report["attack_categories"], {"benign": 2, "dos": 1, "xss": 1})
        self.assertEqual(report["full_rows"]["duplicate_occurrences"], 1)
        self.assertEqual(report["common_vectors"]["duplicate_occurrences"], 2)
        self.assertEqual(report["common_vectors"]["conflicting_groups"], 1)
        self.assertEqual(report["common_vectors"]["conflicting_rows"], 3)
        self.assertEqual(report["common_vectors"]["conflicting_normal_rows"], 2)
        self.assertEqual(report["common_vectors"]["max_group_size"], 3)
        self.assertEqual(report["column_summaries"]["IN_BYTES"]["observed_types"], {"integer": 3, "decimal": 1})
        self.assertEqual(report["grouping_metadata_candidates"], [])
        self.assertFalse(report["matches_published_totals"])

    def test_missing_invalid_and_suspicious_values_are_reported(self):
        invalid = {
            **self.benign, "IPV4_SRC_ADDR": "example.invalid", "IN_PKTS": "",
            "FLOW_DURATION_MILLISECONDS": "-7", "L7_PROTO": "NaN", "L4_DST_PORT": "70000",
            "MIN_TTL": "--5", "MAX_TTL": "-0", "Label": "1",
        }
        self.write_csv([invalid])
        report = audit_dataset(self.path)
        columns = report["column_summaries"]
        self.assertEqual(columns["IPV4_SRC_ADDR"]["observed_types"], {"invalid_ipv4": 1})
        self.assertEqual(columns["IN_PKTS"]["missing"], 1)
        self.assertEqual(columns["FLOW_DURATION_MILLISECONDS"]["negative"], 1)
        self.assertEqual(columns["L7_PROTO"]["nonfinite"], 1)
        self.assertEqual(columns["L4_DST_PORT"]["above_expected_maximum"], 1)
        self.assertEqual(columns["MIN_TTL"]["observed_types"], {"invalid_numeric": 1})
        self.assertEqual(columns["MAX_TTL"]["zeros"], 1)
        self.assertEqual(report["row_flags"]["binary_category_disagreement"], 1)
        self.assertEqual(report["feature_rejections_by_first_error"], {"FLOW_DURATION_MILLISECONDS.invalid_integer": 1})
        self.assertEqual(report["common_vectors"]["rows"], 0)

    def test_reports_additional_grouping_metadata_without_using_it_as_a_predictor(self):
        self.write_csv(
            [{**self.benign, "CAPTURE_START_TIME": "T1"}, {**self.benign, "CAPTURE_START_TIME": "T2"}],
            (*PUBLISHED_COLUMNS, "CAPTURE_START_TIME"),
        )
        report = audit_dataset(self.path)
        self.assertEqual(report["grouping_metadata_candidates"], ["CAPTURE_START_TIME"])
        self.assertEqual(report["full_rows"]["duplicate_occurrences"], 0)
        self.assertEqual(report["common_vectors"]["duplicate_occurrences"], 1)

    def test_rejects_a_truncated_record_and_cleans_scratch(self):
        self.write_csv([self.benign])
        with self.path.open("a", encoding="utf-8") as file:
            file.write("short,record\n")
        with self.assertRaisesRegex(ValueError, "CSV record 2 has 2 fields"):
            audit_dataset(self.path, chunk_bytes=420)
        self.assertEqual(list(self.folder.iterdir()), [self.path])

    def test_rejects_a_missing_required_column(self):
        cols = (*SOURCE_COLUMNS[:-1], "Label", "Attack")
        self.write_csv([], cols)
        with self.assertRaisesRegex(ValueError, "missing required fields: OUT_BYTES"):
            audit_dataset(self.path)

    def test_detects_source_replacement_with_same_size_and_modified_time(self):
        self.write_csv([self.benign])
        info = self.path.stat()
        replacement = self.folder / "replacement.csv"
        replacement.write_bytes(self.path.read_bytes().replace(b"192.0.2.10", b"192.0.2.11"))
        utime(replacement, ns=(info.st_atime_ns, info.st_mtime_ns))

        def replace_after_read(rows):
            if rows is None:
                replacement.replace(self.path)

        with self.assertRaisesRegex(ValueError, "Source CSV changed"):
            audit_dataset(self.path, progress=replace_after_read)

    def test_join_separator_collisions_are_avoided(self):
        self.assertNotEqual(raw_row_key(["a\x1fb", "c"]), raw_row_key(["a", "b\x1fc"]))
