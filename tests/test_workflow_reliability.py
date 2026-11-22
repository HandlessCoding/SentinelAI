"""Validate the complete CSV workflow and exercise isolated local outages."""

from datetime import UTC, datetime
from pathlib import Path
import socket
from tempfile import TemporaryDirectory
import unittest

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

from backend.batch_processing import request_digest
from backend.database import database_url, get_session
from backend.main import create_app
from backend.models import Alert, AnalystNote, Incident, PredictionBatch
from ml.inference import ArtifactError, load_model
from support import requires_local_model
from test_csv_upload import SAMPLE, make_csv
from test_investigations import PostgreSQLSchemaTestCase


SYNTHETIC_CSV = Path(__file__).resolve().parents[1] / "examples" / "unsw_nb15_inference.csv"


def oversized_csv_records():
    return [{**SAMPLE, "service": "\x01" * 80_000, "dur": str(index)} for index in range(5)]


def preview_synthetic_csv(client):
    return client.post(
        "/csv/preview",
        content=SYNTHETIC_CSV.read_bytes(),
        headers={"Content-Type": "text/csv"},
    )


class FullCSVWorkflowTests(PostgreSQLSchemaTestCase):
    def test_csv_receipts_preserve_large_batches_saved_before_json_limits(self):
        records = oversized_csv_records()
        body = make_csv(records)
        headers = {"Content-Type": "text/csv"}
        key = f"csv-{request_digest(records)}-1"
        digest = request_digest(records)
        with self.make_client(lambda _: self.fail("Receipt lookup must not score records")) as client:
            preview = client.post("/csv/preview", content=body, headers=headers)
            self.assertEqual(preview.status_code, 200, preview.text)
            self.assertEqual(preview.json()["upload_id"], digest)
            oversized = client.post("/analyze", json={"records": records}, headers={"Idempotency-Key": key})
            self.assertEqual(oversized.status_code, 413, oversized.text)
            missing = client.post("/csv/receipts", content=body, headers=headers)
            self.assertEqual(missing.status_code, 200, missing.text)
            self.assertEqual(missing.json(), {})
            with Session(self.engine, expire_on_commit=False) as database, database.begin():
                batch = PredictionBatch(
                    idempotency_key=key, request_sha256=digest,
                    record_count=len(records), model_version="fixture-rf",
                    decision_threshold=0.5, prediction_timestamp=datetime.now(UTC),
                )
                database.add(batch)
                database.flush()
                alert = Alert(batch_id=batch.id, record_index=2, attack_probability=0.8)
                database.add(alert)
            found = client.post("/csv/receipts", content=body, headers=headers)
            self.assertEqual(found.status_code, 200, found.text)
            self.assertEqual(found.json()[key]["batch_id"], str(batch.id))
            self.assertEqual(found.json()[key]["alert_ids"], [str(alert.id)])
            self.assertEqual(found.json()[key]["record_count"], len(records))
            with Session(self.engine) as database, database.begin():
                database.get(PredictionBatch, batch.id).request_sha256 = "0" * 64
            conflict = client.post("/csv/receipts", content=body, headers=headers)
            self.assertEqual(conflict.status_code, 409, conflict.text)
        self.assertEqual(self.count(PredictionBatch), 1)
        self.assertEqual(self.count(Alert), 1)

    def test_split_csv_window_commits_and_retries_without_duplicate_alerts(self):
        records = oversized_csv_records()
        key = f"csv-{request_digest(records)}-1-part"
        fail_last_part = True

        def predict(rows):
            if len(rows) == 1 and fail_last_part:
                raise RuntimeError("Synthetic scoring failure")
            return [{"label": 1, "classification": "attack", "attack_probability": 0.8} for _ in rows]

        with self.make_client(predict) as client:
            first = {"records": records[:4]}
            first_key = {"Idempotency-Key": key + "-1"}
            saved = client.post("/analyze", json=first, headers=first_key)
            self.assertEqual(saved.status_code, 201, saved.text)
            last = {"records": records[4:]}
            last_key = {"Idempotency-Key": key + "-2"}
            with self.assertLogs("backend.routes", level="ERROR"):
                failed = client.post("/analyze", json=last, headers=last_key)
            self.assertEqual(failed.status_code, 500)
            self.assertEqual(self.count(PredictionBatch), 1)
            self.assertEqual(self.count(Alert), 4)
            replayed = client.post("/analyze", json=first, headers=first_key)
            self.assertEqual(replayed.status_code, 200, replayed.text)
            self.assertEqual(replayed.json(), saved.json())
            fail_last_part = False
            completed = client.post("/analyze", json=last, headers=last_key)
            self.assertEqual(completed.status_code, 201, completed.text)
        self.assertEqual(self.count(PredictionBatch), 2)
        self.assertEqual(self.count(Alert), 5)

    def test_csv_receipts_can_recover_a_single_legacy_unshippable_row(self):
        large_field = "\x01" * 120_000
        records = [{**SAMPLE, "proto": large_field, "service": large_field, "state": large_field}]
        digest = request_digest(records)
        key = f"csv-{digest}-1"
        with Session(self.engine, expire_on_commit=False) as database, database.begin():
            batch = PredictionBatch(
                idempotency_key=key, request_sha256=digest, record_count=1, model_version="fixture-rf",
                decision_threshold=0.5, prediction_timestamp=datetime.now(UTC),
            )
            database.add(batch)
        with self.make_client(lambda _: self.fail("Receipt lookup must not score records")) as client:
            body = make_csv(records)
            headers = {"Content-Type": "text/csv"}
            preview = client.post("/csv/preview", content=body, headers=headers)
            self.assertEqual(preview.status_code, 413, preview.text)
            found = client.post("/csv/receipts", content=body, headers=headers)
            self.assertEqual(found.status_code, 200, found.text)
            self.assertEqual(found.json()[key]["batch_id"], str(batch.id))
        self.assertEqual(self.count(PredictionBatch), 1)

    @requires_local_model
    def test_csv_to_investigation_persists_and_replays_after_startup(self):
        with self.make_client() as client:
            preview = preview_synthetic_csv(client)
            self.assertEqual(preview.status_code, 200, preview.text)
            data = preview.json()
            self.assertEqual(len(data["columns"]), 42)
            records = data["records"]
            body = {"records": records}
            headers = {"Idempotency-Key": f"csv-{data['upload_id']}-1"}
            prediction = client.post("/predict", json=body)
            self.assertEqual(prediction.status_code, 200, prediction.text)
            predictions = prediction.json()["predictions"]
            self.assertEqual([item["label"] for item in predictions], [0, 1, 1])
            self.assertEqual(self.count(PredictionBatch), 0)
            self.assertEqual(self.count(Alert), 0)

            saved = client.post("/analyze", json=body, headers=headers)
            self.assertEqual(saved.status_code, 201, saved.text)
            receipt = saved.json()
            self.assertEqual(receipt["record_count"], len(records))
            listing = client.get("/alerts", params={"batch_id": receipt["batch_id"]})
            self.assertEqual(listing.status_code, 200, listing.text)
            alerts = {alert["record_index"]: alert for alert in listing.json()}
            self.assertEqual(set(alerts), {1, 2})
            self.assertEqual([alerts[index]["id"] for index in (1, 2)], receipt["alert_ids"])
            for index, alert in alerts.items():
                self.assertEqual(alert["classification"], "suspected_attack")
                self.assertEqual(alert["attack_probability"], predictions[index]["attack_probability"])

            title = "Analyst's synthetic CSV review"
            opened = client.post("/incidents", json={
                "title": title, "alert_ids": receipt["alert_ids"],
            })
            self.assertEqual(opened.status_code, 201, opened.text)
            incident = f"/incidents/{opened.json()['id']}"
            changed = client.patch(incident, json={"status": "investigating"})
            self.assertEqual(changed.status_code, 200, changed.text)
            self.assertEqual(changed.json()["status"], "investigating")
            note_text = "The analyst's review is in progress."
            added = client.post(incident + "/notes", json={
                "author": "Demo analyst", "text": note_text,
            })
            self.assertEqual(added.status_code, 201, added.text)

        with self.make_client() as restarted:
            retry = restarted.post("/analyze", json=body, headers=headers)
            self.assertEqual(retry.status_code, 200, retry.text)
            self.assertEqual(retry.json(), receipt)
            persisted = restarted.get(incident)
            self.assertEqual(persisted.status_code, 200, persisted.text)
            self.assertEqual(persisted.json()["title"], title)
            self.assertEqual(persisted.json()["status"], "investigating")
            self.assertEqual(persisted.json()["notes"][0]["text"], note_text)

        self.assertEqual(self.count(PredictionBatch), 1)
        self.assertEqual(self.count(Alert), 2)
        self.assertEqual(self.count(Incident), 1)
        self.assertEqual(self.count(AnalystNote), 1)


class DependencyOutageTests(unittest.TestCase):
    @requires_local_model
    def test_database_connection_refusal_keeps_scoring_available(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reserved:
            # Reserve a local port without listening. Leave the actual service running.
            reserved.bind(("127.0.0.1", 0))
            port = reserved.getsockname()[1]
            url = database_url(testing=True).set(host="127.0.0.1", port=port)
            engine = create_engine(
                url, connect_args={"connect_timeout": 2}, hide_parameters=True, poolclass=NullPool,
            )
            self.addCleanup(engine.dispose)
            app = create_app()

            def unreachable_session():
                with Session(engine) as session:
                    yield session

            app.dependency_overrides[get_session] = unreachable_session
            with TestClient(app, base_url="http://127.0.0.1") as client:
                preview = preview_synthetic_csv(client)
                self.assertEqual(preview.status_code, 200, preview.text)
                payload = {"records": preview.json()["records"]}
                with self.assertLogs("backend.main", level="ERROR") as logs:
                    listing = client.get("/alerts")
                    saved = client.post(
                        "/analyze", json=payload, headers={"Idempotency-Key": "outage-check"},
                    )
                for response in (listing, saved):
                    self.assertEqual(response.status_code, 503, response.text)
                    self.assertEqual(response.json(), {"detail": "Database unavailable."})
                self.assertEqual(logs.output, [
                    "ERROR:backend.main:Database request failed (OperationalError)",
                    "ERROR:backend.main:Database request failed (OperationalError)",
                ])
                self.assertEqual(client.get("/health").json(), {"status": "ok"})
                prediction = client.post("/predict", json=payload)
                self.assertEqual(prediction.status_code, 200, prediction.text)
                self.assertEqual(
                    [item["label"] for item in prediction.json()["predictions"]], [0, 1, 1],
                )

    def test_missing_real_package_prevents_api_startup(self):
        with TemporaryDirectory() as directory:
            artifact = Path(directory) / "missing-artifact"
            app = create_app(lambda: load_model(artifact))
            with self.assertRaises(ArtifactError):
                with TestClient(app, base_url="http://127.0.0.1"):
                    self.fail("The API must fail startup when its model package is missing.")
