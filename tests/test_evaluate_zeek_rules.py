"""Verify coverage and rate calculations independently of any attack recordings."""

import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from ml.evaluate_zeek_rules import count_rows, evaluate, report_counts
from ml.lab_demo import demo
from ml.lab_registry import read_object, register
from ml.lab_zeek import parse_flow
from test_zeek_traffic import stand_in_capture


def row(label, state, *, protocol="tcp"):
    # Stand-ins for normalized flows and their independent label decisions.
    flow = parse_flow({"proto": protocol, "conn_state": state})
    return flow, (label, None, "outside_reviewed_window" if label == "unknown" else "reviewed_window")


class RuleEvaluationTests(unittest.TestCase):
    def test_scores_eligible_rows_and_keeps_unknowns_and_exclusions_separate(self):
        rows = [row("attack", "S0"), row("benign", "REJ"), row("benign", "SF"), row("attack", "SF"),
                row("unknown", "REJ"), row("benign", "SF", protocol="udp"), row("attack", None),
                row("benign", "UNRECOGNIZED")]
        report = report_counts(count_rows("authorized_lab", rows))
        self.assertEqual(report["confusion"], {"tp": 1, "fp": 1, "tn": 1, "fn": 1})
        self.assertEqual(report["metrics"], {"precision": 0.5, "recall": 0.5, "false_positive_rate": 0.5})
        self.assertTrue(report["positive_class_evaluation_available"])
        self.assertEqual(report["coverage"], {
            "records": 8, "synthetic": 0, "unknown": 1, "unknown_reasons": {"outside_reviewed_window": 1},
            "excluded_reviewed": 3, "exclusion_reasons": {
                "outside_tcp_scope": 1, "missing_tcp_state": 1, "unrecognized_tcp_state": 1,
            },
            "reviewed_benign": 4, "reviewed_attack": 3, "eligible_reviewed": 4,
            "eligible_benign": 2, "eligible_attack": 2,
        })
        self.assertEqual(report["findings_by_rule"], {"tcp-no-response-v1": 1, "tcp-rejected-v1": 1})

    def test_rates_depend_on_their_own_denominators(self):
        benign = report_counts(count_rows("authorized_lab", [row("benign", "SF")]))
        self.assertEqual(benign["metrics"], {"precision": None, "recall": None, "false_positive_rate": 0.0})
        self.assertFalse(benign["positive_class_evaluation_available"])
        flag = report_counts(count_rows("authorized_lab", [row("benign", "REJ")]))
        self.assertEqual(flag["metrics"], {"precision": 0.0, "recall": None, "false_positive_rate": 1.0})
        attack = report_counts(count_rows("authorized_lab", [row("attack", "SF")]))
        self.assertEqual(attack["metrics"], {"precision": None, "recall": 0.0, "false_positive_rate": None})

    def test_synthetic_records_are_coverage_only(self):
        with TemporaryDirectory() as directory:
            root = Path(directory) / "lab"
            demo(root)
            result = evaluate([(root, "fixture")])["overall"]
        self.assertEqual(result["coverage"]["synthetic"], 3)
        self.assertEqual(result["coverage"]["reviewed_attack"], 0)
        self.assertEqual(result["coverage"]["eligible_reviewed"], 0)
        self.assertEqual(result["confusion"], dict.fromkeys(("tp", "fp", "tn", "fn"), 0))
        self.assertTrue(all(value is None for value in result["metrics"].values()))

    def test_group_counts_track_participation_and_duplicates_are_rejected(self):
        with TemporaryDirectory() as directory:
            root = Path(directory) / "lab"
            spec = stand_in_capture(root)
            item = (root, spec["capture_id"])
            result = evaluate([item])
            self.assertEqual(result["overall"]["confusion"], {"tp": 0, "fp": 1, "tn": 0, "fn": 0})
            self.assertEqual(len(result["sessions"]), 1)
            self.assertEqual(len(result["environments"]), 1)
            self.assertEqual({device["device_id"] for device in result["devices"]}, set(spec["device_ids"]))
            self.assertTrue(all(device["coverage"]["records"] == 3 for device in result["devices"]))
            with self.assertRaisesRegex(ValueError, "duplicate capture ID"):
                evaluate([item, item])
            copy = {**read_object(root / "capture-draft.json"), "capture_id": "same-pcap"}
            register(root, copy)
            with self.assertRaisesRegex(ValueError, "duplicate PCAP or Zeek log"):
                evaluate([item, (root, "same-pcap")])

    def test_read_only_audit_of_g27_and_g29_controls(self):
        g27, g29 = (os.environ.get(name) for name in ("SENTINELAI_G27_LAB_ROOT", "SENTINELAI_G29_LAB_ROOT"))
        if not g27 or not g29:
            self.skipTest("requires the locally authorized G27 and G29 capture registries")
        ids = ("g27-pilot-02", "g27-expand-02", "g27-expand-03", "g27-expand-04")
        cohort = [(Path(g27), name) for name in ids]
        cohort.append((Path(g29), "g29-control-01"))
        result = evaluate(cohort)
        self.assertEqual(len(result["captures"]), 5)
        self.assertEqual(len(result["sessions"]), 5)
        self.assertEqual(len(result["devices"]), 2)
        self.assertEqual(len(result["environments"]), 1)
        self.assertEqual(result["lineage_warnings"], [])
        self.assertEqual(result["overall"]["coverage"]["records"], 19)
        self.assertEqual(result["overall"]["coverage"]["exclusion_reasons"], {"outside_tcp_scope": 6})
        self.assertEqual(result["overall"]["confusion"], {"tp": 0, "fp": 0, "tn": 13, "fn": 0})
