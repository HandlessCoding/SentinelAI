"""Exercise offline Zeek imports and API queries in disposable PostgreSQL schemas."""

from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Barrier
from unittest.mock import Mock, patch
from uuid import uuid4

from sqlalchemy.orm import Session

from backend.models import Alert, ZeekCapture, ZeekFlow
from backend.zeek_ingest import import_capture
from ml.lab_demo import demo
from ml.lab_registry import ZEEK_SETTINGS, digest, read_object, register, write_new_object
from test_investigations import PostgreSQLSchemaTestCase


def stand_in_capture(root, *, invalid_port=False, environment_id=None):
    """Build a stand-in receipt and registry only inside an isolated test."""
    demo(root)
    spec = read_object(root / "capture-draft.json")
    spec.update(capture_id="test-reviewed", source="authorized_lab", conn_log="reviewed.jsonl",
                zeek_receipt="receipt.json", authorization="permission.json")
    if environment_id is not None:
        spec["environment_id"] = environment_id
    spec["windows"] = spec["windows"][:1]
    spec["windows"][0]["evidence_kind"] = "independent_annotation"
    source = (root / "fixture-conn.jsonl").read_text(encoding="utf-8")
    rows = [json.loads(line) for line in source.splitlines()]
    rows[0].update(proto="tcp", conn_state="REJ", ground_truth="attack", service="https")
    rows[1].update(proto="tcp", conn_state="S0", duration=None, orig_bytes=None)
    rows[2]["id.resp_p"] = 65536 if invalid_port else 0
    conn_log = root / spec["conn_log"]
    conn_log.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    write_new_object(root / spec["authorization"], {"fixture_only": True})
    write_new_object(root / spec["zeek_receipt"], {
        "version": 1, "settings": list(ZEEK_SETTINGS), "zeek_version": "test fixture",
        "pcap_sha256": digest(root / spec["pcap"], pcap=True), "conn_sha256": digest(conn_log),
    })
    register(root, spec)
    return spec


class ZeekTrafficTests(PostgreSQLSchemaTestCase):
    def setUp(self):
        super().setUp()
        folder = TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name) / "lab"

    def ingest(self, capture_id, root=None):
        with Session(self.engine) as db:
            return import_capture(db, root or self.root, capture_id)

    def test_import_uses_the_receipt_bytes_that_were_verified(self):
        spec = stand_in_capture(self.root)
        receipt = (self.root / spec["zeek_receipt"]).resolve()
        alternate = self.root / "changed-receipt.json"
        write_new_object(alternate, {**read_object(receipt), "zeek_version": "unverified replacement"})
        original_open = Path.open
        receipt_reads = 0

        def open_receipt(path, *args, **kwargs):
            nonlocal receipt_reads
            if path == receipt:
                receipt_reads += 1
                if receipt_reads > 1:
                    path = alternate
            return original_open(path, *args, **kwargs)

        with patch.object(Path, "open", new=open_receipt):
            self.ingest(spec["capture_id"])
        with self.make_client(prediction=Mock()) as client:
            flow = client.get("/traffic/flows").json()["flows"][0]
            detail = client.get("/traffic/flows/" + flow["id"]).json()
            self.assertEqual(detail["capture"]["zeek_version"], "test fixture")
        self.assertEqual(receipt_reads, 1)

    def test_import_filters_and_details_keep_findings_separate_from_ground_truth(self):
        spec = stand_in_capture(self.root)
        capture_id = spec["capture_id"]
        self.assertFalse(self.ingest(capture_id)["replayed"])
        self.assertTrue(self.ingest(capture_id)["replayed"])
        with self.make_client(prediction=Mock(side_effect=AssertionError("traffic must not use ML"))) as client:
            self.assertEqual(client.get("/traffic/summary").json(), {
                "total_flows": 3, "finding_count": 2,
                "protocols": [{"protocol": "tcp", "count": 2}, {"protocol": "udp", "count": 1}],
            })
            result = client.get("/traffic/flows", params={"capture_id": capture_id, "protocol": "tcp", "limit": 1})
            self.assertEqual(result.status_code, 200, result.text)
            first = result.json()
            self.assertEqual(first["next_offset"], 1)
            self.assertEqual(first["flows"][0]["ground_truth"], "unknown")
            self.assertEqual(first["flows"][0]["finding"]["code"], "tcp-no-response-v1")
            unknown = client.get("/traffic/flows/" + first["flows"][0]["id"]).json()
            self.assertIsNone(unknown["duration_ns"])
            self.assertIsNone(unknown["orig_bytes"])
            result = client.get("/traffic/flows", params={"connection_state": "REJ", "has_finding": "true"})
            self.assertEqual(len(result.json()["flows"]), 1)
            flow_id = result.json()["flows"][0]["id"]
            detail_response = client.get("/traffic/flows/" + flow_id)
            self.assertEqual(detail_response.status_code, 200, detail_response.text)
            detail = detail_response.json()
            self.assertEqual(detail["ground_truth"], "benign")
            self.assertEqual(detail["finding"]["source"], "rule")
            self.assertEqual(detail["finding"]["code"], "tcp-rejected-v1")
            self.assertEqual(detail["observed_at"], "2026-01-01T00:00:01.000000000Z")
            self.assertEqual(detail["orig_pkts"], "1")
            self.assertEqual(detail["orig_ip_bytes"], "32")
            self.assertEqual(detail["capture"]["conn_sha256"], digest(self.root / spec["conn_log"]))
            self.assertEqual(client.get("/traffic/flows", params={"limit": 101}).status_code, 422)
            self.assertEqual(client.get("/traffic/flows/" + str(uuid4())).status_code, 404)
        self.assertEqual(self.count(ZeekCapture), 1)
        self.assertEqual(self.count(ZeekFlow), 3)
        self.assertEqual(self.count(Alert), 0)

    def test_concurrent_retry_has_one_writer_and_duplicate_capture_bytes_are_rejected(self):
        spec = stand_in_capture(self.root)
        barrier = Barrier(2, timeout=10)

        def attempt():
            barrier.wait()
            return self.ingest(spec["capture_id"])["replayed"]

        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertEqual(sorted(pool.map(lambda _: attempt(), range(2))), [False, True])
        duplicate = {**spec, "capture_id": "copied-capture"}
        register(self.root, duplicate)
        with self.assertRaisesRegex(ValueError, "already imported"):
            self.ingest(duplicate["capture_id"])
        conflicting = self.root.parent / "different-provenance"
        stand_in_capture(conflicting, environment_id="different-fixture-environment")
        with self.assertRaisesRegex(ValueError, "different provenance"):
            self.ingest(spec["capture_id"], conflicting)
        self.assertEqual(self.count(ZeekCapture), 1)
        self.assertEqual(self.count(ZeekFlow), 3)

    def test_synthetic_malformed_and_oversized_sources_are_rejected_before_writes(self):
        spec = stand_in_capture(self.root, invalid_port=True)
        capture_id = spec["capture_id"]
        with self.assertRaisesRegex(ValueError, "synthetic captures"):
            self.ingest("fixture")
        with self.assertRaisesRegex(ValueError, "Zeek row 3"):
            self.ingest(capture_id)
        with patch("backend.zeek_ingest.MAX_ROWS", 2), self.assertRaisesRegex(ValueError, "limit of 2 flows"):
            self.ingest(capture_id)
        with patch("backend.zeek_ingest.MAX_ARTIFACT_BYTES", 16), self.assertRaisesRegex(ValueError, "size limit"):
            self.ingest(capture_id)
        self.assertEqual(self.count(ZeekCapture), 0)
        self.assertEqual(self.count(ZeekFlow), 0)

    def test_recorded_g29_control_imports_with_three_reviewed_benign_flows(self):
        path = os.environ.get("SENTINELAI_G29_LAB_ROOT")
        if not path:
            self.skipTest("set SENTINELAI_G29_LAB_ROOT to verify the authorized recorded control")
        self.assertEqual(self.ingest("g29-control-01", Path(path))["flow_count"], 3)
        with self.make_client(prediction=Mock()) as client:
            response = client.get("/traffic/summary")
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(response.json(), {"total_flows": 3, "finding_count": 0, "protocols": [
                {"protocol": "tcp", "count": 2}, {"protocol": "udp", "count": 1},
            ]})
            flows = client.get("/traffic/flows").json()["flows"]
            self.assertEqual([flow["ground_truth"] for flow in flows], ["benign"] * 3)
            self.assertEqual(self.count(Alert), 0)
