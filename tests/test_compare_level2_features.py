"""Synthetic checks for G15 feature ambiguity and overlap measurements."""

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from ml.audit_level2_data import PUBLISHED_COLUMNS
from ml.compare_level2_features import compare_rows, sampled_rows
from ml.level2_feature_sets import FEATURE_SETS
from ml.level2_splits import fold_for_vector


class CompareLevel2FeaturesTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.folder = Path(temporary.name)
        self.record = dict.fromkeys(PUBLISHED_COLUMNS, "0")
        self.record.update(
            IPV4_SRC_ADDR="192.0.2.10", IPV4_DST_ADDR="198.51.100.2",
            PROTOCOL="6", L4_SRC_PORT="12345", L4_DST_PORT="443",
            IN_PKTS="1", IN_BYTES="48", MIN_IP_PKT_LEN="48", MAX_IP_PKT_LEN="48",
            Attack="Benign",
        )

    def compare(self, rows, names, *, diagnostic=None):
        records = (tuple(row[name] for name in PUBLISHED_COLUMNS) for row in rows)
        return compare_rows(
            records, PUBLISHED_COLUMNS, names, self.folder, chunk_bytes=400,
            diagnostic=diagnostic,
        )

    def test_common_cohort_conflicts_and_minority_disagreements(self):
        attack = {**self.record, "Label": "1", "Attack": "DoS", "L4_DST_PORT": "53"}
        report = self.compare([self.record, attack, self.record], ("core", "core_ports"))
        core = report["comparisons"]["core"]
        ports = report["comparisons"]["core_ports"]
        self.assertEqual(report["joint_rows"], 3)
        self.assertEqual(core["conflicting_rows"], 3)
        self.assertEqual(core["minority_rows"], 1)
        self.assertEqual(core["zero_duration_conflict_rows"], 3)
        self.assertEqual(core["single_packet_conflict_rows"], 3)
        self.assertEqual(core["largest"], {"rows": 3, "benign": 2, "attack": 1})
        self.assertEqual(ports["conflicting_rows"], 0)
        self.assertEqual(ports["duplicate_occurrences"], 1)
        self.assertFalse(list(self.folder.iterdir()))

    def test_missing_fields_and_protocol_specific_nulls_are_distinct(self):
        invalid = {**self.record, "L4_SRC_PORT": "", "Label": "1", "Attack": "DoS"}
        icmp = {**invalid, "PROTOCOL": "1"}
        report = self.compare([self.record, invalid, icmp], ("core", "core_ports"))
        self.assertEqual(report["joint_rows"], 2)
        self.assertEqual(report["raw_missing"]["L4_SRC_PORT"], 2)
        observed = report["comparisons"]["core_ports"]
        self.assertEqual(observed["rejections"], {"L4_SRC_PORT.missing": 1})
        self.assertEqual(observed["structural_nulls"], {"src_port": 1, "dst_port": 1})

    def test_vector_isolation_can_leave_endpoint_and_tuple_overlap(self):
        spec = FEATURE_SETS["core"]
        first_fold = fold_for_vector(spec.pack(spec.select(self.record)))
        options = (
            {**self.record, "FLOW_DURATION_MILLISECONDS": str(duration)} for duration in range(1, 50)
        )
        second = next(row for row in options if fold_for_vector(spec.pack(spec.select(row))) != first_fold)
        report = self.compare([self.record, second, self.record], ("core",), diagnostic="core")
        result = report["proxy_overlap"]
        self.assertEqual(result["exact_vector_overlap"], 0)
        self.assertIsNone(result["capture_overlap"])
        self.assertIsNone(result["session_overlap"])
        self.assertEqual(result["endpoint_pairs"]["rows_in_shared_groups"], 3)
        self.assertEqual(result["transport_five_tuples"]["shared_groups"], 1)
        self.assertNotIn(self.record["IPV4_SRC_ADDR"], json.dumps(report))

    def test_sample_selects_unique_reproducible_ordinals_and_verifies_release_rows(self):
        lines = [f"{row},data\n" for row in range(25)]
        selected = list(sampled_rows(iter(lines), 25, 10, 42))
        self.assertEqual(selected, list(sampled_rows(iter(lines), 25, 10, 42)))
        self.assertEqual(len({record[0] for record in selected}), 10)
        self.assertEqual(sorted(int(record[0]) for record in selected), [int(row[0]) for row in selected])
        with self.assertRaisesRegex(ValueError, "fewer|ended"):
            list(sampled_rows(iter(lines), 26, 10, 42))
        with self.assertRaisesRegex(ValueError, "more physical rows"):
            list(sampled_rows(iter(lines), 24, 10, 42))
