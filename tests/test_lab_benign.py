"""Exercise the G27 collector's plan, evidence review, and serial handoff."""

from base64 import b64encode
from copy import deepcopy
from decimal import Decimal
from io import BytesIO
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import tarfile
import unittest
from unittest.mock import patch

from ml.lab_benign import CLIENT, SENSOR, UDP_PORT, plan, verify_isolation
from ml.lab_benign_audit import PROBES, evidence_key, review, summarize
from ml.lab_benign_transfer import read_export, recover_export
from ml.lab_registry import read_object
from ml.lab_zeek import parse_flow


CAPTURE = "test-capture"
TIMESTAMP = "2026-01-01T00:00:00Z"


def config():
    return {"version": 1, "sessions": [{
        "capture_id": CAPTURE, "session_id": "test-session", "seed": 11,
        "connections": [{"method": "udp", "requests": 2, "min_bytes": 5, "max_bytes": 8,
                         "delay_ms": 10, "gap_ms": 50}],
    }]}


def fixture():
    spec, groups = plan(config())[CAPTURE]
    ends = [CLIENT, 43210, SENSOR, UDP_PORT]
    flow = parse_flow({"ts": 1_767_225_602, "duration": Decimal("0.20"), "proto": "udp",
                       "orig_pkts": 2, "resp_pkts": 2, "orig_ip_bytes": 73, "resp_ip_bytes": 120,
                       "missed_bytes": 0, "conn_state": "SF",
                       **dict(zip(("id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p"), ends))})
    evidence = {}
    for role, address in (("client", CLIENT), ("sensor", SENSOR)):
        evidence[role] = {
            "capture_id": CAPTURE, "isolation": {"role": role, "local": address, "checked_utc": TIMESTAMP,
                "no_route": PROBES, "forwarding": False, "lab_route": "10.75.26.0/24"},
            "events": [{"id": t.id, "start": f"2026-01-01T00:00:02.{i}Z",
                        "end": f"2026-01-01T00:00:02.{i}5Z", "endpoints": ends, **evidence_key(t)}
                       for i, t in enumerate(groups[0])],
        }
    evidence["sensor"].update(scenario=spec, start="2026-01-01T00:00:01Z", end="2026-01-01T00:00:03Z")
    return spec, groups, evidence["client"], evidence["sensor"], [flow]


class BenignLabTests(unittest.TestCase):
    def test_shipped_plans_are_deterministic_and_have_disjoint_sessions(self):
        pilot = plan(read_object(Path("examples/lab_benign_pilot.json")))
        expansion = plan(read_object(Path("examples/lab_benign_expansion.json")))
        self.assertEqual(pilot, plan(read_object(Path("examples/lab_benign_pilot.json"))))
        self.assertEqual([len(groups) for _, groups in pilot.values()], [3])
        self.assertFalse(pilot.keys() & expansion.keys())
        self.assertEqual([len(groups) for _, groups in expansion.values()], [4, 5, 4])

    def test_plan_rejects_unbounded_or_repeated_inputs(self):
        document = config()
        step = document["sessions"][0]["connections"][0]
        for key, value in (("max_bytes", 513), ("requests", 5), ("gap_ms", 0), ("method", "external")):
            with self.subTest(key=key), self.assertRaises(ValueError):
                changed = deepcopy(document)
                changed["sessions"][0]["connections"][0] = {**step, key: value}
                plan(changed)
        document["sessions"].append(deepcopy(document["sessions"][0]))
        with self.assertRaisesRegex(ValueError, "unique"):
            plan(document)
        with self.assertRaisesRegex(ValueError, "session fields"):
            plan({"version": 1, "sessions": [0]})

    def test_isolation_refuses_an_extra_interface(self):
        links = json.dumps([{"ifname": name} for name in ("lo", "lab0", "nat0")]).encode()
        with patch("ml.lab_benign.subprocess.check_output", return_value=links), self.assertRaisesRegex(
                ValueError, "dedicated lab interface"):
            verify_isolation("client", {})

    def test_application_evidence_must_match_outcomes_and_complete_flows(self):
        spec, groups, client, sensor, flows = fixture()
        review(spec, groups, client, sensor, flows)
        broken = deepcopy(sensor)
        broken["events"][0]["response_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "application evidence disagrees"):
            review(spec, groups, client, broken, flows)
        with self.assertRaisesRegex(ValueError, "distinct Zeek flow"):
            review(spec, groups, client, sensor, flows * 2)
        client["isolation"]["no_route"] = []
        with self.assertRaisesRegex(ValueError, "isolation evidence"):
            review(spec, groups, client, sensor, flows)

    def test_summary_reports_missing_without_changing_counts(self):
        summary = summarize(fixture()[-1])
        self.assertEqual(summary["protocol"], {"udp": 1})
        self.assertEqual(summary["features"]["service"], {"missing": 1, "invalid": 0})
        self.assertEqual(summary["numerical"]["duration_ns"]["median"], 200_000_000)

    def test_serial_import_checks_expected_files_and_unique_frames(self):
        body = b"benign fixture"
        data = BytesIO()
        with tarfile.open(fileobj=data, mode="w:gz") as archive:
            info = tarfile.TarInfo("./evidence/test.json")
            info.size = len(body)
            archive.addfile(info, BytesIO(body))
        frame = b"G27_EXPORT:00001:" + b64encode(data.getvalue()) + b"\n"
        with TemporaryDirectory() as folder:
            console = Path(folder) / "serial.log"
            console.write_bytes(b"G27_EXPORT_BEGIN\n" + frame + b"G27_EXPORT_END\n")
            self.assertEqual(read_export(console, {"evidence/test.json"}), {"evidence/test.json": body})
            with self.assertRaisesRegex(ValueError, "unexpected"):
                read_export(console, {"evidence/elsewhere.json"})
            console.write_bytes(b"G27_EXPORT_BEGIN\n" + frame * 2 + b"G27_EXPORT_END\n")
            with self.assertRaisesRegex(ValueError, "repeated"):
                recover_export(console)
