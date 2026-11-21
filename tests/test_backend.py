"""Exercise the HTTP contract with model doubles and the saved local package."""

from pathlib import Path
import unittest
from unittest.mock import Mock

from fastapi.testclient import TestClient

from backend.main import app, create_app
from backend.schemas import MAX_BATCH_SIZE
from ml.inference import ArtifactError, FEATURE_TYPES, InputValidationError, read_prediction_csv


class MockedBackendTests(unittest.TestCase):
    def setUp(self):
        self.model = Mock(model_version="fixture-model", decision_threshold=0.5)
        self.attack = {"label": 1, "classification": "attack", "attack_probability": 0.8}
        self.model.predict.side_effect = lambda records: [self.attack for _ in records]
        self.loader = Mock(return_value=self.model)
        self.client = self.enterContext(TestClient(create_app(self.loader)))

    def test_health_model_info_and_predictions_share_one_startup_load(self):
        self.assertEqual(self.client.get("/health").json(), {"status": "ok"})
        self.assertEqual(self.client.get("/model/info").json(), {
            "model_version": "fixture-model",
            "expected_feature_count": len(FEATURE_TYPES),
            "decision_threshold": 0.5,
        })
        records = [{"service": "-", "is_ftp_login": 4}]
        for _ in range(2):
            response = self.client.post("/predict", json={"records": records})
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json(), {
                "model_version": "fixture-model",
                "decision_threshold": 0.5,
                "predictions": [self.attack],
            })
        self.assertEqual(self.model.predict.call_count, 2)
        self.model.predict.assert_called_with(records)
        self.loader.assert_called_once_with()

    def test_accepts_batch_at_the_limit(self):
        response = self.client.post("/predict", json={"records": [{}] * MAX_BATCH_SIZE})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.json()["predictions"]), MAX_BATCH_SIZE)

    def test_invalid_envelopes_fail_before_inference(self):
        for body in (
            {}, [], {"records": None}, {"records": {}}, {"records": [42]},
            {"records": []}, {"records": [{}] * (MAX_BATCH_SIZE + 1)},
            {"records": [{}], "model_path": "private_value"},
        ):
            with self.subTest(body=body):
                response = self.client.post("/predict", json=body)
                self.assertEqual(response.status_code, 422)
                self.assertEqual(response.json(), {"detail": "Provide a records array with 1 to 100 objects."})
        self.model.predict.assert_not_called()

    def test_malformed_json_returns_sanitized_400(self):
        response = self.client.post(
            "/predict", content='{"private_value":', headers={"Content-Type": "application/json"}
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"detail": "Malformed JSON."})
        self.model.predict.assert_not_called()

    def test_inference_validation_returns_sanitized_422(self):
        self.model.predict.side_effect = InputValidationError("internal parser path and request value")
        response = self.client.post("/predict", json={"records": [{}]})
        self.assertEqual(response.status_code, 422)
        self.assertEqual(response.json(), {
            "detail": "Records must match the expected UNSW-NB15 feature schema."
        })

    def test_unexpected_prediction_failure_returns_sanitized_500(self):
        self.model.predict.side_effect = RuntimeError("private internal model directory")
        with self.assertLogs("backend.routes", level="ERROR") as logs:
            response = self.client.post("/predict", json={"records": [{}]})
        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.json(), {"detail": "Prediction failed."})
        self.assertEqual(logs.output, ["ERROR:backend.routes:Prediction failed (RuntimeError)"])

    def test_docs_include_routes_bounds_and_complete_example(self):
        self.assertIn("Swagger UI", self.client.get("/docs").text)
        spec = self.client.get("/openapi.json").json()
        self.assertTrue({"/health", "/model/info", "/predict"} <= set(spec["paths"]))
        body_schema = spec["components"]["schemas"]["PredictRequest"]
        self.assertEqual(body_schema["properties"]["records"]["maxItems"], 100)
        self.assertEqual(set(body_schema["examples"][0]["records"][0]), set(FEATURE_TYPES))


class RealBackendTests(unittest.TestCase):
    def test_startup_fails_when_the_configured_artifact_cannot_be_loaded(self):
        unavailable = Mock(side_effect=ArtifactError("package unavailable"))
        with self.assertRaises(ArtifactError):
            with TestClient(create_app(unavailable)):
                self.fail("App should only start after loading the model")
        unavailable.assert_called_once_with()

    def test_scores_synthetic_records_using_the_existing_package(self):
        sample = Path(__file__).resolve().parents[1] / "examples" / "unsw_nb15_inference.csv"
        records = list(read_prediction_csv(sample))
        with TestClient(app, base_url="http://127.0.0.1") as client:
            info = client.get("/model/info").json()
            self.assertEqual(info, {
                "model_version": "unsw-nb15-rf-v1",
                "expected_feature_count": 42,
                "decision_threshold": 0.5,
            })
            response = client.post("/predict", json={"records": records})
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()["predictions"], app.state.model.predict(records))
            self.assertEqual([item["label"] for item in response.json()["predictions"]], [0, 1, 1])
            for invalid_record in ({"service": "-"}, {**records[0], "dur": "invalid"}):
                with self.subTest(invalid_record=invalid_record):
                    invalid = client.post("/predict", json={"records": [invalid_record]})
                    self.assertEqual(invalid.status_code, 422)
