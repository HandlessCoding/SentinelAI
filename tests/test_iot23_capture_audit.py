"""Synthetic Zeek fixtures for the offline G21 preflight."""

from collections import Counter
from hashlib import sha256
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from ml.audit_iot23_captures import Capture, ROLES, audit, coverage


FIELDS = (
    "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto",
    "duration", "orig_pkts", "resp_pkts", "orig_ip_bytes", "resp_ip_bytes",
    "label", "detailedlabel",
)


def flow(**updates):
    values = dict(zip(FIELDS, (
        "1540000000.125", "C-test", "192.0.2.1", "12345", "198.51.100.2", "443", "tcp",
        "1.02", "4", "4", "240", "240", "Benign", "-",
    ), strict=True))
    values.update(updates)
    return values


class IoT23CaptureAuditTests(unittest.TestCase):
    def setUp(self):
        folder = TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name)
        self.manifest = self.root / "manifest.json"

    def capture(self, name, role, rows, *, negative_evidence=None, original_group=None, device_group=None):
        path = self.root / f"{name}.labeled"
        header = ["#separator \\x09", "#unset_field\t-", "#empty_field\t(empty)",
                  "#fields\t" + "\t".join(FIELDS), "#types\t" + "\t".join(["string"] * len(FIELDS))]
        body = ["\t".join(row[field] for field in FIELDS) if isinstance(row, dict) else row for row in rows]
        path.write_text("\n".join(header + body + ["#close\t2018-12-31-00-00-00", ""]), encoding="utf-8")
        return {
            "capture_id": name, "original_group": original_group or name,
            "device_group": device_group, "role": role,
            "log": path.name, "sha256": sha256(path.read_bytes()).hexdigest(),
            "negative_evidence": negative_evidence,
        }

    def run_audit(self, *captures):
        self.manifest.write_text(json.dumps(captures), encoding="utf-8")
        return audit(self.manifest, chunk_bytes=512)

    def test_labels_missing_counters_and_record_duplicates(self):
        entry = self.capture("mixed", "fit", [
            flow(), flow(label="Background"), flow(label="-"),
            flow(label="Malicious", detailedlabel="C&C-Test"),
            flow(label="Malicious", detailedlabel="C&C-Test"),
            flow(label="Malicious", detailedlabel="Test", orig_ip_bytes="-"),
            flow(label="Malicious", detailedlabel="Test", resp_pkts="NaN"),
            "bad\twidth",
        ])
        result = self.run_audit(entry)
        result_capture = result["captures"][0]
        self.assertEqual(result_capture["quality"]["records"], 8)
        self.assertEqual(result_capture["quality"]["malformed_width"], 1)
        self.assertEqual(result_capture["quality"]["invalid_resp_pkts"], 1)
        self.assertEqual(result_capture["missing"]["orig_ip_bytes"], 1)
        self.assertEqual(result_capture["classes"], {"unverified_benign": 1, "unknown": 2, "explicit_malicious": 4})
        self.assertEqual(result_capture["eligible"], {"explicit_malicious": 2})
        self.assertEqual(result_capture["eligible_categories"], {"C&C-Test": 2})
        self.assertEqual(result["overlap"]["record"]["duplicate_occurrences_by_capture"]["mixed"], 1)
        self.assertEqual(sha256((self.root / entry["log"]).read_bytes()).hexdigest(), entry["sha256"])

    def test_recurring_vectors_and_tuples_are_distinct_from_same_start(self):
        first = self.capture("a", "fit", [flow()], negative_evidence="Synthetic clean capture")
        second = self.capture("b", "validation", [flow(**{
            "ts": "1540000009.125", "uid": "C-new", "duration": "1.0200", "label": "Malicious",
            "id.orig_h": "198.51.100.2", "id.orig_p": "443", "id.resp_h": "192.0.2.1", "id.resp_p": "12345",
        })])
        result = self.run_audit(first, second)
        counts = result["overlap"]
        boundary = "fit to validation"
        self.assertEqual(counts["vector"]["shared_between_roles"][boundary]["left_verified_benign"], 1)
        self.assertEqual(counts["tuple"]["shared_between_roles"][boundary]["right_explicit_malicious"], 1)
        self.assertEqual(counts["tuple_at_start"]["shared_between_roles"][boundary]["keys"], 0)
        self.assertIn("validation has fewer than two original capture groups with eligible attacks",
                      result["automatic_failures"])

    def test_original_group_device_and_shared_start_are_flagged(self):
        first = self.capture("a", "fit", [flow()], original_group="somfy", device_group="device-a")
        second = self.capture("b", "comparison", [flow(label="Malicious", uid="C-different")],
                              original_group="somfy", device_group="device-a")
        result = self.run_audit(first, second)
        self.assertIn("original_group somfy crosses roles", result["automatic_failures"])
        self.assertIn("device_group device-a crosses roles", result["automatic_failures"])
        self.assertIn("fit to comparison requires review of shared tuple_at_start keys",
                      result["automatic_failures"])
        self.assertTrue(result["requires_provenance_and_label_review"])

    def test_bad_digest_is_rejected(self):
        entry = self.capture("a", "fit", [flow()])
        with (self.root / entry["log"]).open("a", encoding="utf-8") as stream:
            stream.write("#changed\n")
        with self.assertRaisesRegex(ValueError, "SHA-256 does not match"):
            self.run_audit(entry)

    def test_coverage_rejects_category_loss_even_when_class_floors_hold(self):
        roles = (*ROLES, "validation")
        captures = [Capture(str(i), str(i), None, role, "", "") for i, role in enumerate(roles)]
        summaries = [{
            "role": item.role, "original_group": item.original_group,
            "classes": Counter(verified_benign=2_000, explicit_malicious=2_000),
            "eligible": Counter(verified_benign=1_000, explicit_malicious=1_000),
            "categories": Counter(Scan=100), "eligible_categories": Counter(Scan=50),
        } for item in captures]
        self.assertEqual(coverage(captures, summaries)[1], [])
        summaries[2]["eligible_categories"]["Scan"] -= 1
        self.assertEqual(coverage(captures, summaries)[1], ["comparison retains fewer than half of Scan"])
