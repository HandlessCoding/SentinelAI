"""Exercise migrations and API persistence in isolated PostgreSQL test schemas."""

from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
from threading import Barrier
from types import SimpleNamespace
import unittest
from unittest.mock import Mock
from uuid import uuid4

from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, inspect, select
from sqlalchemy.orm import Session
from sqlalchemy.schema import CreateSchema, DropSchema

from backend.database import database_url, get_session
from backend.main import create_app
from backend.models import Alert, AnalystNote, Incident, PredictionBatch
from ml.inference import read_prediction_csv


ROOT = Path(__file__).resolve().parents[1]
REVISION = "0002_zeek_traffic"
requires_local_model = unittest.skipIf(
    os.environ.get("SENTINELAI_CI_SYNTHETIC_ONLY") == "1",
    "requires the locally frozen Level 1 model package",
)


class PostgreSQLSchemaTestCase(unittest.TestCase):
    """Give each test a freshly migrated schema in the dedicated database."""

    def setUp(self):
        test_url = database_url(testing=True)
        schema = f"g7_test_{uuid4().hex}"
        admin = create_engine(test_url, hide_parameters=True)
        self.addCleanup(admin.dispose)
        with admin.begin() as connection:
            self.assertEqual(connection.exec_driver_sql("SELECT current_database()").scalar_one(),
                             test_url.database)
            connection.execute(CreateSchema(schema))
        self.addCleanup(self.drop_schema, admin, schema)
        self.engine = create_engine(
            test_url, hide_parameters=True, connect_args={"options": f"-csearch_path={schema}"}
        )
        self.addCleanup(self.engine.dispose)
        self.migrate(command.upgrade, "head")

    def drop_schema(self, admin, schema):
        with admin.begin() as connection:
            connection.execute(DropSchema(schema, cascade=True))

    def migrate(self, operation, *args):
        config = Config(str(ROOT / "alembic.ini"))
        with self.engine.begin() as connection:
            config.attributes["connection"] = connection
            operation(config, *args)

    def make_client(self, prediction=None):
        if prediction is None:
            app = create_app()
        else:
            model = SimpleNamespace(model_version="fixture-rf", decision_threshold=0.5, predict=prediction)
            app = create_app(lambda: model)

        def session():
            with Session(self.engine, expire_on_commit=False) as database:
                yield database

        app.dependency_overrides[get_session] = session
        return TestClient(app, base_url="http://127.0.0.1")

    def count(self, model):
        with Session(self.engine) as session:
            return session.scalar(select(func.count()).select_from(model))


class PostgreSQLInvestigationsTests(PostgreSQLSchemaTestCase):
    def test_migration_up_down_and_orm_schema_match(self):
        existing = {"prediction_batches", "alerts", "incidents", "analyst_notes", "alembic_version"}
        expected = existing | {"zeek_captures", "zeek_flows"}
        self.assertEqual(set(inspect(self.engine).get_table_names()), expected)
        with self.engine.connect() as connection:
            self.assertEqual(connection.exec_driver_sql("SELECT version_num FROM alembic_version").scalar_one(),
                             REVISION)
        self.migrate(command.check)
        self.migrate(command.downgrade, "0001_alert_investigations")
        self.assertEqual(set(inspect(self.engine).get_table_names()), existing)
        with Session(self.engine) as db, db.begin():
            db.add(Incident(title="Existing Level 1 investigation"))
        self.migrate(command.upgrade, "head")
        self.assertEqual(self.count(Incident), 1)
        self.migrate(command.downgrade, "base")
        self.assertEqual(set(inspect(self.engine).get_table_names()), {"alembic_version"})
        self.migrate(command.upgrade, "head")
        self.assertEqual(set(inspect(self.engine).get_table_names()), expected)

    @requires_local_model
    def test_saved_model_workflow_persists_across_app_lifespans(self):
        records = list(read_prediction_csv(ROOT / "examples" / "unsw_nb15_inference.csv"))
        with self.make_client() as client:
            result = client.post("/predict", json={"records": records})
            self.assertEqual(result.status_code, 200)
            scored = result.json()["predictions"]
            self.assertEqual(self.count(PredictionBatch), 0)
            self.assertEqual(self.count(Alert), 0)
            created = client.post("/analyze", json={"records": records}, headers={"Idempotency-Key": "workflow"})
            self.assertEqual(created.status_code, 201, created.text)
            receipt = created.json()
            self.assertEqual(receipt["record_count"], 3)
            self.assertEqual(len(receipt["alert_ids"]), 2)
            self.assertEqual(self.count(Incident), 0)
            alert_id = receipt["alert_ids"][0]
            first = client.get(f"/alerts/{alert_id}").json()
            self.assertEqual(first["classification"], "suspected_attack")
            self.assertEqual(first["investigation_status"], "unreviewed")
            self.assertEqual(first["attack_probability"], scored[1]["attack_probability"])
            self.assertEqual(first["model_version"], receipt["model_version"])
            self.assertEqual(first["prediction_timestamp"], receipt["prediction_timestamp"])
            self.assertEqual(first["batch_id"], receipt["batch_id"])
            self.assertEqual(first["record_index"], 1)
            filtered = client.get("/alerts", params={
                "batch_id": receipt["batch_id"], "status": "unreviewed", "min_probability": 0.85
            })
            self.assertEqual([alert["id"] for alert in filtered.json()], [alert_id])
            incident = client.post("/incidents", json={"title": "Synthetic case", "alert_ids": [alert_id]})
            self.assertEqual(incident.status_code, 201, incident.text)
            incident_id = incident.json()["id"]
            self.assertEqual(incident.json()["status"], "open")
            self.assertEqual(incident.json()["alert_ids"], [alert_id])
            patch = client.patch(f"/incidents/{incident_id}", json={"status": "investigating"})
            self.assertEqual(patch.status_code, 200)
            self.assertEqual(patch.json()["status"], "investigating")
            note = client.post(f"/incidents/{incident_id}/notes", json={"author": "Analyst", "text": "Reviewing."})
            self.assertEqual(note.status_code, 201)
            self.assertEqual(note.json()["text"], "Reviewing.")

        with self.make_client() as other:
            alert = other.get(f"/alerts/{alert_id}").json()
            self.assertEqual(alert["investigation_status"], "investigating")
            self.assertEqual(alert["incident_id"], incident_id)
            persisted = other.get(f"/incidents/{incident_id}").json()
            self.assertEqual(persisted["notes"][0]["text"], "Reviewing.")
        self.assertEqual(self.count(PredictionBatch), 1)
        self.assertEqual(self.count(Alert), 2)
        self.assertEqual(self.count(Incident), 1)
        self.assertEqual(self.count(AnalystNote), 1)

    def test_exact_replay_conflict_and_no_duplicate_rows(self):
        prediction = Mock(return_value=[{"label": 1, "attack_probability": 0.9}])
        with self.make_client(prediction) as client:
            headers = {"Idempotency-Key": "same-batch"}
            create = client.post("/analyze", json={"records": [{"dur": 1, "proto": "tcp"}]}, headers=headers)
            replay = client.post("/analyze", json={"records": [
                {"proto": "tcp", "id": 200, "dur": 1}
            ]}, headers=headers)
            conflict = client.post("/analyze", json={"records": [{"dur": 2, "proto": "tcp"}]}, headers=headers)
        self.assertEqual(create.status_code, 201)
        self.assertEqual(replay.status_code, 200)
        self.assertEqual(replay.json(), create.json())
        self.assertEqual(conflict.status_code, 409)
        prediction.assert_called_once()
        self.assertEqual(self.count(PredictionBatch), 1)
        self.assertEqual(self.count(Alert), 1)

    def test_concurrent_submission_creates_only_one_batch(self):
        both_predicting = Barrier(2, timeout=5)

        def predict(_records):
            both_predicting.wait()
            return [{"label": 1, "attack_probability": 0.9}]

        with self.make_client(predict) as client:
            def submit():
                return client.post("/analyze", json={"records": [{"dur": 1}]},
                                   headers={"Idempotency-Key": "concurrent"})

            with ThreadPoolExecutor(max_workers=2) as executor:
                responses = [executor.submit(submit) for _ in range(2)]
                first, second = (response.result(timeout=10) for response in responses)
        self.assertEqual(sorted([first.status_code, second.status_code]), [200, 201])
        self.assertEqual(first.json(), second.json())
        self.assertEqual(self.count(PredictionBatch), 1)
        self.assertEqual(self.count(Alert), 1)

    def test_rejects_invalid_requests_and_duplicate_incident_assignment(self):
        prediction = Mock(return_value=[{"label": 1, "attack_probability": 0.9}])
        with self.make_client(prediction) as client:
            self.assertEqual(client.post("/analyze", json={"records": [{}]}).status_code, 422)
            created = client.post("/analyze", json={"records": [{}]}, headers={"Idempotency-Key": "one"})
            alert_id = created.json()["alert_ids"][0]
            self.assertEqual(client.get("/alerts", params={"min_probability": 2}).status_code, 422)
            self.assertEqual(client.post("/incidents", json={
                "title": "Case", "alert_ids": [alert_id, alert_id]
            }).status_code, 422)
            self.assertEqual(client.post("/incidents", json={
                "title": "Case", "alert_ids": [str(uuid4())]
            }).status_code, 404)
            body = {"title": "Case", "alert_ids": [alert_id]}
            case = client.post("/incidents", json=body)
            self.assertEqual(case.status_code, 201)
            self.assertEqual(client.post("/incidents", json=body).status_code, 409)
            incident = "/incidents/" + case.json()["id"]
            self.assertEqual(client.patch(incident, json={"status": "confirmed"}).status_code, 422)
            self.assertEqual(client.post(incident + "/notes", json={"author": "a", "text": " "}).status_code, 422)
        self.assertEqual(self.count(Incident), 1)
        self.assertEqual(self.count(AnalystNote), 0)

    def test_database_error_sanitizes_response_and_rolls_back_batch(self):
        prediction = Mock(return_value=[{"label": 1, "attack_probability": 2.0}])
        with self.make_client(prediction) as client, self.assertLogs("backend.main", level="ERROR") as logs:
            response = client.post("/analyze", json={"records": [{}]}, headers={"Idempotency-Key": "rollback"})
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json(), {"detail": "Database unavailable."})
        self.assertEqual(logs.output, ["ERROR:backend.main:Database request failed (IntegrityError)"])
        self.assertEqual(self.count(PredictionBatch), 0)
        self.assertEqual(self.count(Alert), 0)
