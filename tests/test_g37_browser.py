"""Run the built dashboard against a disposable database and a real ingestion worker."""

import os
import socket
import subprocess
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event
from time import monotonic, sleep

import httpx
import uvicorn
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.staticfiles import StaticFiles
from test_investigations import ROOT, PostgreSQLSchemaTestCase
from test_workflow_reliability import make_csv, oversized_csv_records

from backend.batch_processing import request_digest
from backend.models import Alert, PredictionBatch, ZeekFlow, ZeekStream
from backend.zeek_stream import Source, run_worker
from verification.g37 import flow_identity


def synthetic_predictions(rows):
    return [{"label": 1, "classification": "attack", "attack_probability": 0.8} for _ in rows]


def dashboard(api):
    assets = StaticFiles(directory=ROOT / "frontend/dist", html=True)

    async def application(scope, receive, send):
        if scope["type"] != "http":
            await api(scope, receive, send)
        elif scope["path"].startswith("/api/"):
            path = scope["path"][4:]
            await api(dict(scope, path=path, raw_path=scope["raw_path"][4:]), receive, send)
        else:
            await assets(scope, receive, send)

    return application


@unittest.skipUnless(
    os.environ.get("SENTINELAI_G37_BROWSER") == "1", "requires the built dashboard and Chromium"
)
class DashboardBrowserTests(PostgreSQLSchemaTestCase):
    def test_worker_rotation_pagination_and_csv_receipt_in_browser(self):
        with (
            TemporaryDirectory() as folder,
            ThreadPoolExecutor(max_workers=2) as pool,
            socket.socket() as listener,
        ):
            log = Path(folder) / "conn.log"
            csv = Path(folder) / "synthetic.csv"
            csv.write_bytes(make_csv(oversized_csv_records()))
            legacy = Path(folder) / "historical.csv"
            self.seed_historical_receipt(legacy)
            source = Source("g37-browser", log, "browser", "development", "fixture", "synthetic")
            log.write_bytes(b"")
            listener.bind(("127.0.0.1", 0))
            origin = f"http://127.0.0.1:{listener.getsockname()[1]}"
            app = dashboard(self.make_client(synthetic_predictions).app)
            server = uvicorn.Server(uvicorn.Config(app, lifespan="on", access_log=False, log_level="warning"))
            stop = Event()
            worker = pool.submit(run_worker, self.engine, source, stop)
            serving = pool.submit(server.run, [listener])
            try:
                self.wait_for_http(origin, serving)
                subprocess.run(
                    ["node", "frontend/e2e/g37.mjs", origin, str(log), str(csv), str(legacy)],
                    cwd=ROOT,
                    check=True,
                    timeout=90,
                )
                self.assert_reconciled(log, source.capture_id)
            finally:
                stop.set()
                server.should_exit = True
                worker.result(timeout=10)
                serving.result(timeout=10)

    def wait_for_http(self, origin, serving):
        deadline = monotonic() + 10
        with httpx.Client(trust_env=False) as client:
            while monotonic() < deadline:
                if serving.done():
                    serving.result()
                    self.fail("Disposable dashboard server stopped before serving")
                try:
                    if client.get(f"{origin}/api/health", timeout=0.5).status_code == 200:
                        return
                except httpx.TransportError:
                    sleep(0.05)
        self.fail("Disposable dashboard server did not start")

    def assert_reconciled(self, log, source_id):
        retained = log.with_suffix(".log.1")
        archive = retained.stat()
        expected = {
            flow_identity(line).stream_key
            for path in (log, retained)
            for line in path.read_bytes().splitlines()
        }
        with Session(self.engine) as reader:
            state = reader.get(ZeekStream, source_id)
            rows = reader.execute(select(ZeekFlow.stream_key, ZeekFlow.ground_truth)).all()
        self.assertEqual(len(expected), 32)
        self.assertCountEqual(rows, [(key, "unknown") for key in expected])
        self.assertEqual(state.last_drained_file, f"{archive.st_dev:x}:{archive.st_ino:x}")
        self.assertEqual((state.byte_offset, state.backlog_bytes), (log.stat().st_size, 0))
        self.assertEqual(self.count(PredictionBatch), 3)
        self.assertEqual(self.count(Alert), 6)

    def seed_historical_receipt(self, csv):
        records = [dict(record, dur=str(index + 100)) for index, record in enumerate(oversized_csv_records())]
        digest = request_digest(records)
        csv.write_bytes(make_csv(records))
        with Session(self.engine) as db, db.begin():
            batch = PredictionBatch(
                idempotency_key=f"csv-{digest}-1",
                request_sha256=digest,
                record_count=len(records),
                model_version="fixture-rf",
                decision_threshold=0.5,
                prediction_timestamp=datetime.now(UTC),
            )
            db.add(batch)
            db.flush()
            db.add(Alert(batch_id=batch.id, record_index=2, attack_probability=0.8))
