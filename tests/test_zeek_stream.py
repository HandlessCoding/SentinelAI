"""Verify stream recovery, offline parity and health in isolated PostgreSQL schemas."""

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event
from time import perf_counter, sleep
import json
import os
import tracemalloc
from unittest.mock import Mock

from sqlalchemy import event
from sqlalchemy.orm import Session

from backend.models import Alert, ZeekFlow, ZeekStream
from backend.zeek_ingest import import_capture
from backend.zeek_stream import MAX_BATCH_BYTES, MAX_BATCH_ROWS, Source, ingest_batch, replay_source, run_worker
from ml.lab_registry import lab_path, load_verified
from test_investigations import PostgreSQLSchemaTestCase
from test_zeek_traffic import stand_in_capture


def record(index, state="REJ"):
    return (json.dumps({"uid": f"C{index}", "ts": 1_700_000_000 + index, "proto": "tcp",
                        "conn_state": state, "ground_truth": "attack"}) + "\n").encode()


class ZeekStreamTests(PostgreSQLSchemaTestCase):
    def setUp(self):
        super().setUp()
        folder = TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name)
        self.path = self.root / "conn.log"
        self.sensor = Source("test-sensor", self.path, "session", "environment", "sensor", "Zeek 8.0.11")

    def ingest(self, source=None):
        with Session(self.engine) as db:
            return ingest_batch(db, source or self.sensor)

    def health(self, client):
        response = client.get("/traffic/monitoring")
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def traffic_client(self):
        return self.make_client(prediction=Mock(side_effect=AssertionError("traffic must not call model inference")))

    def wait_for(self, load, accept):
        deadline = perf_counter() + 10
        while perf_counter() < deadline:
            result = load()
            if accept(result):
                return result
            sleep(0.025)
        self.fail("background ingestion did not reach the expected state")

    def test_restart_partial_lines_malformed_rows_and_duplicate_replay(self):
        with self.traffic_client() as client:
            self.ingest()
            self.assertEqual(self.health(client)["sources"][0]["status"], "waiting")
            first, second = record(1), record(2)
            self.path.write_bytes(first + b"{broken}\n" + second[:25])
            self.ingest()
            self.assertEqual(self.health(client)["sources"][0]["backlog_bytes"], 25)
            self.assertEqual(self.count(ZeekFlow), 1)
            with self.path.open("ab") as writer:
                writer.write(second[25:] + first)

            def crash(_session):
                raise RuntimeError("interrupted before commit")

            with Session(self.engine) as db:
                event.listen(db, "before_commit", crash, once=True)
                with self.assertRaisesRegex(RuntimeError, "interrupted"):
                    ingest_batch(db, self.sensor)
            self.assertEqual(self.count(ZeekFlow), 1)
            self.assertEqual(self.health(client)["sources"][0]["backlog_bytes"], 25)
            self.ingest()
            self.ingest()
            result = self.health(client)
            source = result["sources"][0]
            self.assertEqual((source["rejected_rows"], source["duplicate_rows"], source["backlog_bytes"]), (1, 1, 0))
            self.assertEqual((result["recent_flows"], result["recent_findings"]), (2, 2))
            page = client.get("/traffic/flows", params={"source": "connected_sensor", "order": "ingested"}).json()
            self.assertEqual([row["ground_truth"] for row in page["flows"]], ["unknown", "unknown"])
            self.assertTrue(all(row["finding"]["code"] == "tcp-rejected-v1" for row in page["flows"]))
            self.assertEqual(self.count(Alert), 0)

    def test_rotation_drains_previous_file_and_missing_archive_blocks_until_restored(self):
        first, second = record(1), record(2)
        self.path.write_bytes(first)
        self.ingest()
        with self.path.open("ab") as writer:
            writer.write(second + b'{"partial"')
        retained = self.root / "retained"
        self.path.rename(retained)
        self.path.write_bytes(first + record(3))
        with self.traffic_client() as client:
            self.ingest()
            self.assertEqual(self.health(client)["sources"][0]["last_error"], "rotated_file_missing")
            self.assertEqual(self.count(ZeekFlow), 1)
            retained.rename(self.root / "conn.log.1")
            self.ingest()
            self.ingest()
            result = self.health(client)["sources"][0]
            self.assertEqual((result["rejected_rows"], result["duplicate_rows"], result["backlog_bytes"]), (1, 1, 0))
            self.assertEqual(self.count(ZeekFlow), 3)
            self.path.write_bytes(record(4))
            self.ingest()
            self.assertEqual(self.health(client)["sources"][0]["last_error"], "checkpoint_content_changed")
            self.assertEqual(self.count(ZeekFlow), 3)

    def test_concurrent_workers_share_one_committed_checkpoint(self):
        self.path.write_bytes(record(1) + record(2))
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(self.ingest) for _ in range(2)]
            self.assertEqual(sorted(future.result(timeout=10) for future in futures), [0, self.path.stat().st_size])
        self.assertEqual(self.count(ZeekFlow), 2)

    def test_large_unterminated_row_has_bounded_reads_and_resumes_after_delimiter(self):
        with self.path.open("wb") as writer:
            for _ in range(16):
                writer.write(b"x" * MAX_BATCH_BYTES)
        tracemalloc.start()
        try:
            consumed = self.ingest()
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
        self.assertLessEqual(consumed, MAX_BATCH_BYTES)
        self.assertLess(peak, 3 * 1024**2)
        while self.ingest():
            pass
        with self.path.open("ab") as writer:
            writer.write(b"\n")
            for i in range(MAX_BATCH_ROWS + 1):
                writer.write(record(i))
        self.ingest()
        self.assertEqual(self.count(ZeekFlow), MAX_BATCH_ROWS - 1)
        self.ingest()
        with Session(self.engine) as db:
            checkpoint = db.get(ZeekStream, self.sensor.capture_id)
            self.assertEqual(checkpoint.rejected_rows, 1)
            self.assertEqual(checkpoint.byte_offset, self.path.stat().st_size)
        self.assertEqual(self.count(ZeekFlow), MAX_BATCH_ROWS + 1)

    def test_replay_labels_are_bound_to_original_bytes_and_offline_rules(self):
        registry = self.root / "registry-root"
        spec = stand_in_capture(registry)
        source = replay_source("replay-fixture", self.path, registry, spec["capture_id"])
        self.path.write_bytes((registry / spec["conn_log"]).read_bytes() + record(88))
        self.ingest(source)
        with Session(self.engine) as db:
            import_capture(db, registry, spec["capture_id"])
        with self.traffic_client() as client:
            self.assertEqual(self.health(client)["sources"][0]["rejected_rows"], 1)
            flows = client.get("/traffic/flows", params={"source": "recorded_replay"}).json()["flows"]
            self.assertEqual(len(flows), 3)
            detail = client.get("/traffic/flows/" + flows[-1]["id"]).json()
            self.assertEqual((detail["ground_truth"], detail["source_offset"]), ("benign", 0))
            self.assertEqual(detail["finding"]["code"], "tcp-rejected-v1")
            self.assertEqual(self.count(ZeekFlow), 6)

    def test_authorized_benign_recordings_end_to_end(self):
        roots = [os.environ.get(f"SENTINELAI_{milestone}_LAB_ROOT") for milestone in ("G26", "G27", "G29")]
        if not all(roots):
            self.skipTest("requires the authorized G26, G27 and G29 capture registries")
        g26, g27, g29 = map(Path, roots)
        captures = [(g26, "g26-benign-01-reviewed"), (g27, "g27-pilot-02"), (g27, "g27-expand-02"),
                    (g27, "g27-expand-03"), (g27, "g27-expand-04"), (g29, "g29-control-01")]
        latencies, backlog_bytes = [], []
        with self.traffic_client() as client, ThreadPoolExecutor(max_workers=1) as pool:
            for index, (root, capture_id) in enumerate(captures):
                manifest, _ = load_verified(root, capture_id)
                log = lab_path(root, manifest["capture"]["conn_log"])
                path = self.root / f"relay-{index}.log"
                source = replay_source(f"replay-{index}", path, root, capture_id)
                with Session(self.engine) as db:
                    import_capture(db, root, capture_id)
                original = log.read_bytes()
                path.write_bytes(original[:1])
                offline = client.get("/traffic/flows", params={"capture_id": capture_id}).json()["flows"]
                stop = Event()
                worker = pool.submit(run_worker, self.engine, source, stop)
                try:
                    def source_backlog():
                        return next((item["backlog_bytes"] for item in self.health(client)["sources"]
                                     if item["capture_id"] == source.capture_id), None)

                    backlog_bytes.append(self.wait_for(source_backlog, lambda size: size == 1))
                    published = perf_counter()
                    with path.open("ab") as writer:
                        writer.write(original[1:])
                    replay = self.wait_for(
                        lambda: client.get("/traffic/flows", params={"capture_id": source.capture_id}).json()["flows"],
                        lambda rows: len(rows) == len(offline),
                    )
                    latencies.append(perf_counter() - published)
                finally:
                    stop.set()
                    worker.result(timeout=10)
                fields = ("observed_at", "proto", "conn_state", "ground_truth", "finding")
                self.assertEqual([[r[k] for k in fields] for r in replay], [[r[k] for k in fields] for r in offline])
                self.assertTrue(all(row["ground_truth"] == "benign" and row["finding"] is None for row in replay))
                self.assertEqual(self.ingest(source), 0)
            result = self.health(client)
            self.assertEqual(result["recent_flows"], 20)
            self.assertEqual(result["recent_findings"], 0)
            self.assertEqual(backlog_bytes, [1] * len(captures))
            self.assertTrue(all(source["backlog_bytes"] == 0 for source in result["sources"]))
            self.assertEqual(self.count(Alert), 0)
            print("Background replay append-to-API latency ms:", [round(t * 1000, 1) for t in latencies],
                  "observed flows/s including idle polling:", round(20 / sum(latencies), 1))
