"""Check the Zeek-native projection and optional real-capture audit."""

import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from backend.zeek_ingest import flow_values
from ml.lab_capture import capture_rows
from ml.lab_demo import demo
from ml.lab_registry import load_verified
from ml.lab_zeek import parse_flow
from ml.zeek_flow_v1 import FIELDS, audit, audit_rows, inspect_predictors, vector_counts


BASE_ROW = {
    "ts": 1_700_000_000, "proto": "tcp", "conn_state": "REJ", "duration": 0,
    "orig_pkts": 1, "resp_pkts": 0, "orig_ip_bytes": 60, "resp_ip_bytes": 0,
}


class ZeekFlowV1Tests(unittest.TestCase):
    def test_projection_matches_ingestion_and_excludes_metadata(self):
        flow = parse_flow({**BASE_ROW, "id.orig_h": "192.0.2.1", "id.resp_p": 12345,
                           "service": "test-service", "uid": "test-uid", "label": "attack"})
        expected, status = inspect_predictors(flow.features, issues=flow.issues)
        stored = flow_values("example-capture", 1, flow, ("benign", None, "reviewed_window"))
        actual, _ = inspect_predictors(stored)
        self.assertEqual(actual, expected)
        self.assertEqual(tuple(actual), FIELDS)
        self.assertEqual(list(actual.values()), ["tcp", 1, 0, 60, 0, 0, "REJ"])
        self.assertEqual(set(status.values()), {"present"})
        self.assertIsNotNone(stored["rule_code"])

    def test_required_and_optional_fields_enforce_types_and_scope(self):
        flow = parse_flow({**BASE_ROW, "duration": None, "conn_state": "-"})
        vector, status = inspect_predictors(flow.features, issues=flow.issues)
        self.assertIsNone(vector["duration_ns"])
        self.assertIsNone(vector["conn_state"])
        self.assertEqual(status["duration_ns"], "missing")
        self.assertEqual(status["conn_state"], "missing")
        cases = (
            ("duration", "invalid", "duration_ns", "invalid"),
            ("conn_state", "UNKNOWN", "conn_state", "unsupported"),
            ("orig_pkts", True, "orig_pkts", "invalid"),
            ("resp_ip_bytes", None, "resp_ip_bytes", "missing"),
            ("orig_ip_bytes", 2**63, "orig_ip_bytes", "invalid"),
            ("proto", "icmp", "proto", "unsupported"),
        )
        for source, value, field, expected in cases:
            with self.subTest(field=field, value=value):
                flow = parse_flow({**BASE_ROW, source: value})
                vector, status = inspect_predictors(flow.features, issues=flow.issues)
                self.assertIsNone(vector)
                self.assertEqual(status[field], expected)

    def test_repeated_vectors_are_retained_without_relabeling_unknown(self):
        flow = parse_flow(BASE_ROW)
        entries = [(flow, (label, None, "fixture")) for label in ("benign", "unknown", "attack")]
        report, vectors, labels = audit_rows(entries)
        self.assertEqual(report["rows"], 3)
        self.assertEqual(report["eligible_by_ground_truth"], {"benign": 1, "attack": 1, "unknown": 1})
        self.assertEqual(labels["benign"], labels["attack"])
        self.assertEqual(vector_counts(vectors), {
            "unique_vectors": 1, "repeated_vectors": 1, "rows_on_repeated_vectors": 3, "extra_rows": 2,
        })
        with patch("ml.zeek_flow_v1.MAX_RECORDS", 2):
            with self.assertRaisesRegex(ValueError, "2 flow records"):
                audit_rows(entries)

    def test_synthetic_cohort_and_duplicate_ids_are_rejected(self):
        with TemporaryDirectory() as folder:
            root = Path(folder) / "lab"
            demo(root)
            with self.assertRaisesRegex(ValueError, "synthetic"):
                audit([(root, "fixture")])
            with self.assertRaisesRegex(ValueError, "duplicate capture ID"):
                audit([(root, "fixture"), (root, "fixture")])

    def test_authorized_capture_cohort_and_ingestion_projection(self):
        roots = [os.environ.get(f"SENTINELAI_{milestone}_LAB_ROOT") for milestone in ("G26", "G27", "G29")]
        if not all(roots):
            self.skipTest("requires the local G26, G27, and G29 registries")
        g26, g27, g29 = map(Path, roots)
        captures = [(g26, "g26-benign-01-reviewed"), (g27, "g27-pilot-02"),
                    (g27, "g27-expand-02"), (g27, "g27-expand-03"), (g27, "g27-expand-04"),
                    (g29, "g29-control-01")]
        report = audit(captures)
        self.assertEqual(report, audit(captures[::-1]))
        self.assertEqual(report["lineage"]["sessions"], 6)
        self.assertEqual(report["overall"]["ground_truth"], {"benign": 20, "attack": 0, "unknown": 0})
        self.assertEqual(report["overall"]["eligible_protocols"], {"tcp": 14, "udp": 6})
        self.assertEqual(report["overall"]["fields"], {field: {"present": 20} for field in FIELDS})
        with self.assertRaisesRegex(ValueError, "duplicate PCAP or Zeek log"):
            audit([captures[0], (g26, "g26-benign-01")])

        for root, capture_id in captures:
            manifest, windows = load_verified(root, capture_id)
            for index, (flow, label) in enumerate(capture_rows(root, manifest, windows), 1):
                stored = flow_values(capture_id, index, flow, label)
                self.assertEqual(inspect_predictors(flow.features, issues=flow.issues), inspect_predictors(stored))
