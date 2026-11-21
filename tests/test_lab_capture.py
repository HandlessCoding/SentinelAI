"""Use synthetic data and a subprocess stub to test the local collection workflow."""

from copy import deepcopy
from decimal import Decimal
import json
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from ml.lab_capture import audit, capture_rows, role_coverage
from ml.lab_demo import demo
from ml.lab_registry import ZEEK_SETTINGS, digest, load_verified, read_object, register, write_new_object
from ml.lab_zeek import parse_flow, read_flows, run_zeek


class CaptureLabTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / "lab"
        self.report = demo(self.root)
        self.spec = read_object(self.root / "capture-draft.json")

    def test_demo_registers_pcap_log_and_independent_fixture_evidence(self):
        manifest, windows = load_verified(self.root, "fixture")
        self.assertEqual(manifest["sha256"]["pcap"], digest(self.root / "fixture.pcap", pcap=True))
        self.assertEqual(manifest["sha256"]["evidence"]["evidence.json"], digest(self.root / "evidence.json"))
        rows = list(capture_rows(self.root, manifest, windows))
        self.assertEqual([label for _, (label, _, _) in rows], ["benign", "attack", "unknown"])
        self.assertEqual(rows[1][1][1], "fixture-only")
        self.assertEqual(rows[0][0].features["orig_ip_bytes"], 32)
        self.assertEqual(rows[0][0].features["duration_ns"], 125_000_000)
        self.assertEqual(self.report["overlap"]["zeek_core"]["global_counts"]["rows_in_label_conflict"], 3)
        self.assertFalse(self.report["passes_automated_gates"])
        self.assertEqual(self.report["roles"]["fit"]["eligible"], {})

    def test_duplicate_id_and_source_tampering_are_rejected(self):
        with self.assertRaises(FileExistsError):
            register(self.root, self.spec)
        with (self.root / "evidence.json").open("a", encoding="utf-8") as stream:
            stream.write("tampered")
        with self.assertRaisesRegex(ValueError, "checksum mismatch"):
            load_verified(self.root, "fixture")

    def test_unsafe_paths_unsupported_evidence_and_overlapping_windows_fail(self):
        spec = deepcopy(self.spec)
        spec.update(capture_id="another", pcap="../fixture.pcap")
        with self.assertRaisesRegex(ValueError, "relative lab path"):
            register(self.root, spec)
        spec["pcap"] = self.spec["pcap"]
        spec["windows"][1]["start"] = spec["windows"][0]["start"]
        with self.assertRaisesRegex(ValueError, "disjoint"):
            register(self.root, spec)
        spec["windows"] = deepcopy(self.spec["windows"])
        spec["windows"][0]["evidence_kind"] = "model_prediction"
        with self.assertRaisesRegex(ValueError, "evidence kind"):
            register(self.root, spec)
        spec["windows"][0]["evidence_kind"] = "synthetic_fixture"
        spec["windows"][0]["reviewer"] = spec["windows"][0]["author"]
        with self.assertRaisesRegex(ValueError, "distinct"):
            register(self.root, spec)

    def test_unverified_end_and_boundary_crossing_stay_unknown(self):
        spec = deepcopy(self.spec)
        spec.update(capture_id="ends", conn_log="ends.jsonl")
        records = [json.loads(line) for line in (self.root / "fixture-conn.jsonl").read_text().splitlines()]
        records[0]["duration"] = "-"
        records[1]["duration"] = 2
        records[2]["ts"] = records[0]["ts"]
        records[2]["duration"] = 0
        records[2].update({"id.orig_h": "198.51.100.11", "id.resp_p": 443, "label": "attack"})
        (self.root / spec["conn_log"]).write_text("".join(json.dumps(row) + "\n" for row in records), encoding="utf-8")
        register(self.root, spec)
        manifest, windows = load_verified(self.root, "ends")
        rows = list(capture_rows(self.root, manifest, windows))
        self.assertEqual([label for _, (label, _, _) in rows], ["unknown", "unknown", "benign"])
        self.assertEqual([reason for _, (_, _, reason) in rows[:2]],
                         ["unverified_flow_end", "crosses_reviewed_boundary"])
        self.assertIsNone(rows[0][0].features["duration_ns"])
        self.assertEqual(rows[2][0].features["duration_ns"], 0)

    def test_missing_and_invalid_features_are_explicit(self):
        flow = parse_flow({"ts": Decimal("1767225600.000001"), "proto": "icmp", "duration": Decimal("NaN"),
                           "orig_ip_bytes": -1, "resp_pkts": True, "service": "-"})
        self.assertEqual(flow.timestamp_ns, 1767225600000001000)
        self.assertFalse(flow.core_eligible)
        self.assertEqual(flow.issues["duration"], "invalid")
        self.assertEqual(flow.issues["service"], "missing")
        self.assertEqual(flow.issues["resp_pkts"], "invalid")
        self.assertIsNone(flow.features["orig_ip_bytes"])
        self.assertEqual(parse_flow({"duration": Decimal("0.000000001000")}).features["duration_ns"], 1)
        self.assertEqual(parse_flow({"duration": Decimal("1e-200000")}).issues["duration"], "invalid")
        bad = self.root / "bad.jsonl"
        bad.write_text("[]\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "line 1"):
            list(read_flows(bad, digest(bad)))

    def test_real_zeek_duration_rounds_up_for_window_attribution(self):
        flow = parse_flow({"ts": Decimal("1795301661.65971"), "duration": Decimal("0.028464078903198242")})
        self.assertEqual(flow.timestamp_ns, 1_795_301_661_659_710_000)
        self.assertEqual(flow.features["duration_ns"], 28_464_079)
        self.assertNotIn("duration", flow.issues)

    def test_audit_reports_shared_vectors_and_group_reuse(self):
        spec = deepcopy(self.spec)
        spec.update(capture_id="linked", role="validation")
        register(self.root, spec)
        result = audit(self.root, ["fixture", "linked"])
        self.assertIn("cross-role session reuse in fixture / linked", result["blockers"])
        self.assertIn("cross-role device reuse in fixture / linked", result["blockers"])
        self.assertIn("same pcap bytes in fixture / linked", result["blockers"])
        self.assertIn("cross-role tuple and start matches need provenance review", result["blockers"])
        shared = result["overlap"]["zeek_core"]["validation_shared"]
        self.assertEqual((shared["keys"], shared["rows"]), (1, 3))

    def test_coverage_counts_independent_attack_sessions_and_retention(self):
        def stats(role, session):
            return {"capture": {"source": "authorized_lab", "role": role, "session_id": session},
                    "labeled": {"benign": 1200, "attack": 1200}, "eligible": {"benign": 1000, "attack": 1000},
                    "attack_categories": {"example": 1200}, "eligible_categories": {"example": 1000}}

        captures = {role: stats(role, role) for role in ("fit", "calibration", "comparison", "validation")}
        self.assertEqual(role_coverage(captures)[1], ["validation needs at least two distinct attack sessions"])
        captures["validation-2"] = stats("validation", "validation-2")
        self.assertEqual(role_coverage(captures)[1], [])
        captures["comparison"]["eligible_categories"]["example"] = 500
        self.assertEqual(role_coverage(captures)[1], ["comparison lacks eligible support for category example"])

    def test_offline_zeek_runner_pins_inputs_settings_and_outputs(self):
        calls = []

        def zeek_stub(args, *, cwd, stdout, **kwargs):
            calls.append(args)
            if args[1:] == ["--version"]:
                stdout.write(b"zeek version fixture\n")
            else:
                (cwd / "conn.log").write_bytes((self.root / "fixture-conn.jsonl").read_bytes())
            return subprocess.CompletedProcess(args, 0)

        with patch("ml.lab_zeek.shutil.which", return_value=str(self.root / "zeek.exe")), \
                patch("ml.lab_zeek.subprocess.run", side_effect=zeek_stub):
            out = run_zeek(self.root, "fixture.pcap", "test-run")
        self.assertEqual(calls[1][1:], ["-r", str(self.root / "fixture.pcap"), *ZEEK_SETTINGS])
        receipt = read_object(out / "run.json")
        self.assertEqual(receipt["conn_sha256"], digest(out / "conn.log"))
        self.assertEqual(receipt["pcap_sha256"], digest(self.root / "fixture.pcap"))
        spec = deepcopy(self.spec)
        spec.update(capture_id="archived", source="authorized_archive", conn_log="zeek/test-run/conn.log",
                    zeek_receipt="zeek/test-run/run.json")
        with self.assertRaisesRegex(ValueError, "permission record"):
            register(self.root, spec)
        spec["authorization"] = "terms.json"
        write_new_object(self.root / "terms.json", {"synthetic test": True})
        for window in spec["windows"]:
            window["evidence_kind"] = "independent_annotation"
        register(self.root, spec)
        load_verified(self.root, "archived")
        with (out / "conn.log").open("a", encoding="utf-8") as stream:
            stream.write("\n")
        with self.assertRaisesRegex(ValueError, "receipt"):
            load_verified(self.root, "archived")

    def test_failed_zeek_command_does_not_publish_a_run(self):
        with patch("ml.lab_zeek.shutil.which", return_value=str(self.root / "zeek.exe")), \
                patch("ml.lab_zeek.subprocess.run", side_effect=subprocess.CalledProcessError(1, ["zeek"])):
            with self.assertRaises(subprocess.CalledProcessError):
                run_zeek(self.root, "fixture.pcap", "failed")
        self.assertFalse((self.root / "zeek" / "failed").exists())
