"""Regression checks for the offline TCP history projection."""

import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from backend.zeek_ingest import flow_values
from ml.lab_demo import demo
from ml.lab_zeek import parse_flow
from ml.zeek_flow_history_v1 import HISTORY_FIELDS, audit_capture, inspect_history_predictors
from ml.zeek_flow_v1 import FIELDS, inspect_predictors


BASE = {
    "ts": 1_700_000_000, "proto": "tcp", "orig_pkts": 4, "resp_pkts": 3,
    "orig_ip_bytes": 160, "resp_ip_bytes": 120, "conn_state": "SF",
}


class ZeekHistoryTests(unittest.TestCase):
    def test_case_sensitive_marker_presence_and_ingestion_parity(self):
        flow = parse_flow({**BASE, "history": "ShADRRFf^X"})
        vector, status = inspect_history_predictors(flow.features, issues=flow.issues)
        self.assertEqual(status, "present")
        self.assertEqual(tuple(vector), (*FIELDS, *HISTORY_FIELDS))
        self.assertEqual({name: vector[name] for name in FIELDS}, inspect_predictors(flow.features)[0])
        self.assertEqual([vector[name] for name in HISTORY_FIELDS], [True, False, True, False])
        stored = flow_values("fixture", 1, flow, ("unknown", None, "fixture"))
        self.assertEqual(inspect_history_predictors(stored), (vector, status))
        responder = parse_flow({**BASE, "history": "Shadr"})
        vector, _ = inspect_history_predictors(responder.features, issues=responder.issues)
        self.assertEqual([vector[name] for name in HISTORY_FIELDS], [False, True, False, True])
        absent = parse_flow({**BASE, "history": "ShAFf"})
        vector, status = inspect_history_predictors(absent.features, issues=absent.issues)
        self.assertEqual(status, "present")
        self.assertEqual([vector[name] for name in HISTORY_FIELDS], [False] * 4)

    def test_unusable_history_preserves_nulls_and_ineligible_base_stays_out(self):
        cases = (
            ({"history": None}, "missing"), ({"history": "-"}, "missing"),
            ({"history": ""}, "invalid"), ({"history": True}, "invalid"),
            ({"history": "Sh D"}, "unsupported"),
            ({"proto": "udp", "history": "Dd"}, "not_applicable"),
        )
        for overrides, expected in cases:
            with self.subTest(overrides=overrides):
                flow = parse_flow({**BASE, **overrides})
                vector, status = inspect_history_predictors(flow.features, issues=flow.issues)
                self.assertEqual(status, expected)
                self.assertEqual([vector[name] for name in HISTORY_FIELDS], [None] * 4)
        flow = parse_flow({**BASE, "orig_pkts": None, "history": "D"})
        self.assertEqual(inspect_history_predictors(flow.features, issues=flow.issues), (None, "ineligible_base"))

    def test_real_capture_audit_rejects_synthetic(self):
        with TemporaryDirectory() as folder:
            root = Path(folder) / "lab"
            demo(root)
            with self.assertRaisesRegex(ValueError, "real capture"):
                audit_capture(root, "fixture")

    def test_authorized_recorded_control(self):
        root = os.environ.get("SENTINELAI_G29_LAB_ROOT")
        if not root:
            self.skipTest("requires the authorized G29 registry")
        report = audit_capture(Path(root), "g29-control-01")
        self.assertEqual(report["history_coverage"], {"present": 2, "not_applicable": 1})
        self.assertEqual(report["marker_rows"], dict(zip(HISTORY_FIELDS, (2, 2, 0, 0), strict=True)))
