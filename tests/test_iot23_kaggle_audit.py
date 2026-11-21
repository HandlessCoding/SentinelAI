"""Synthetic fixtures for the G24 read-only CSV preflight."""

from collections import Counter
import csv
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from ml.audit_iot23_kaggle import COLUMNS, Capture, assess_roles, audit, unpack_label


def flow(*, label="Malicious", detail="Synthetic category", **updates):
    values = dict(zip(COLUMNS, (
        "1540000000.125", "C-example", "192.0.2.1", "12345", "198.51.100.2", "443", "tcp",
        "-", "-", "-", "-", "S0", "-", "-", "0", "S", "1", "60", "0", "0",
        f"-   {label}   {detail}",
    ), strict=True))
    values.update(updates)
    return values


class KaggleIoT23AuditTests(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.pins = {}

    def write(self, number, *records):
        path = self.root / f"dataset{number}.csv"
        with path.open("w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=COLUMNS)
            writer.writeheader()
            writer.writerows(records)
        self.pins[number] = sha256(path.read_bytes()).hexdigest()

    def run_audit(self, *captures):
        return audit(self.root, self.root, self.pins, captures=captures, chunk_bytes=512)

    def test_combined_label_and_unknown_values(self):
        self.assertEqual(unpack_label("-   BENIGN   -"), (0, "-"))
        self.assertEqual(unpack_label("-   Malicious   C&C Compound Category"), (1, "C&C Compound Category"))
        self.assertEqual(unpack_label("-   Background   -"), (None, "-"))
        with self.assertRaises(ValueError):
            unpack_label("-   Benign")

    def test_missing_duration_preserves_known_rows_and_unknown_exclusion(self):
        self.write(1, flow(), flow(label="Background", duration="0"),
                   flow(label="Benign", duration="0", **{"orig_pkts": "NaN"}))
        report = self.run_audit(Capture(1, "capture-a", "fit"))
        detail = report["captures"]["dataset1.csv"]
        self.assertEqual(detail["observed"], {"malicious": 1, "benign": 1, "unknown": 1})
        self.assertEqual(detail["eligible_duration_free"], {"malicious": 1})
        self.assertEqual(detail["eligible_duration_required"], {})
        self.assertEqual(detail["issues"]["duration_unset_malicious"], 1)
        self.assertEqual(detail["issues"]["invalid_or_unset_counter_benign"], 1)
        self.assertTrue(report["requires_label_authority_and_capture_review"])

    def test_counts_overlap_without_treating_benign_as_verified(self):
        self.write(1, flow())
        self.write(2, flow(label="Benign", duration="1", **{
            "id.orig_h": "198.51.100.2", "id.orig_p": "443", "id.resp_h": "192.0.2.1", "id.resp_p": "12345",
        }))
        out = self.run_audit(Capture(1, "capture-a", "fit"), Capture(2, "capture-b", "validation"))
        self.assertEqual(out["overlap"]["vector"]["global_counts"]["rows_in_label_conflict"], 2)
        hit = out["overlap"]["tuple_at_start"]["shared_between_roles"]["fit to validation"]
        self.assertEqual(hit["keys"], 1)
        self.assertEqual(hit["right_benign_labeled"], 1)
        self.assertNotIn("right_verified_benign", hit)
        self.assertIn("validation has fewer than two original groups with eligible attacks",
                      out["nominal_coverage_failures"]["duration_free"])

    def test_missing_file_is_reported_and_modified_content_fails(self):
        self.write(1, flow())
        first = Capture(1, "capture-a", "fit")
        other = Capture(2, "capture-b", "validation")
        self.assertEqual(self.run_audit(first, other)["missing_captures"]["dataset2.csv"]["role"], "validation")
        self.pins[1] = "00" * 32
        with self.assertRaisesRegex(ValueError, "pinned SHA-256"):
            self.run_audit(first, other)

    def test_category_floor_can_fail_even_with_enough_rows(self):
        support = {
            "role": "comparison", "dedicated_benign_eligible": 0,
            "observed": Counter(benign=1_000, malicious=1_000),
            "eligible_duration_free": Counter(benign=1_000, malicious=1_000),
            "eligible_duration_required": Counter(benign=1_000, malicious=1_000),
            "attack_categories": Counter(scan=100),
            "duration_free_categories": Counter(scan=50),
            "duration_required_categories": Counter(scan=49),
        }
        _, failures = assess_roles({"dataset1.csv": support})
        self.assertNotIn("comparison lacks eligible support for category scan", failures["duration_free"])
        self.assertIn("comparison lacks eligible support for category scan", failures["duration_required"])
