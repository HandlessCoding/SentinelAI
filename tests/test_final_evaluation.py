"""Check held-out evaluation using tiny synthetic CSVs and frozen scores."""

import csv
from contextlib import redirect_stderr, redirect_stdout
from hashlib import sha256
import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch

import numpy as np

from ml import evaluate_final
from ml.inference import (
    ARTIFACT_FORMAT_VERSION, DECISION_THRESHOLD, FEATURE_TYPES, MODEL_VERSION, InferenceModel, feature_schema,
    runtime_versions,
)


def write_records(path, rows, *, reorder=False):
    columns = ["id", *FEATURE_TYPES, "attack_cat", "label"]
    if reorder:
        columns.reverse()
    with path.open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=columns)
        writer.writeheader()
        for record_id, duration, label, category in rows:
            record = dict.fromkeys(FEATURE_TYPES, "0")
            record.update({
                "id": record_id,
                "dur": duration,
                "proto": "tcp",
                "service": "-",
                "state": "FIN",
                "label": label,
                "attack_cat": category,
            })
            writer.writerow(record)


class FinalEvaluationTests(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.training_csv = self.root / "synthetic-training.csv"
        self.test_csv = self.root / "synthetic-held-out.csv"
        write_records(self.training_csv, [
            (1, "1", 0, "Normal"),
            (2, "1", 1, "Generic"),
            (3, "2.0", 0, "Normal"),
            (4, "3", 0, "Normal"),
            (5, "4", 1, "Exploits"),
        ])
        write_records(self.test_csv, [
            (101, "1", 1, "Generic"),
            (102, "3", 0, "Normal"),
            (103, "2", 1, "Fuzzers"),
            (104, "3", 1, "Exploits"),
            (105, "4", 0, "Normal"),
            (106, "7", 1, "Exploits"),
            (107, "8", 0, "Normal"),
        ], reorder=True)
        self.test_digest = sha256(self.test_csv.read_bytes()).hexdigest()

        probabilities = {1: 0.9, 2: 0.55, 3: 0.5, 4: 0.8, 7: 0.2, 8: 0.4}

        def predict_proba(batch):
            scores = [probabilities[duration] for duration in batch[:, 0]]
            return np.array([[1 - score, score] for score in scores])

        self.pipeline = Mock(spec_set=["predict_proba"])
        self.pipeline.predict_proba.side_effect = predict_proba
        self.model = InferenceModel(MODEL_VERSION, DECISION_THRESHOLD, self.pipeline)

    def evaluate(self):
        return evaluate_final.evaluate_files(self.model, self.training_csv, self.test_csv, batch_size=2)

    def test_metrics_use_frozen_scores_and_fixed_threshold(self):
        report = self.evaluate()
        metrics = report["metrics"]
        self.assertEqual(report["test_class_counts"], {"normal": 3, "attack": 4})
        self.assertEqual(metrics["confusion_matrix"], [[2, 1], [2, 2]])
        expected = {
            "accuracy": 4 / 7,
            "balanced_accuracy": 7 / 12,
            "precision": 2 / 3,
            "recall": 1 / 2,
            "f1": 4 / 7,
            "false_positive_rate": 1 / 3,
            "roc_auc": 13 / 24,
            "average_precision": (1 + 2 / 3 + 3 / 5 + 4 / 7) / 4,
        }
        for name, value in expected.items():
            with self.subTest(metric=name):
                self.assertAlmostEqual(metrics[name], value)

    def test_category_recall_and_normal_false_alarms(self):
        report = self.evaluate()
        self.assertEqual(report["attack_categories"], {
            "Generic": {"support": 1, "detected": 1, "missed": 0, "recall": 1.0},
            "Fuzzers": {"support": 1, "detected": 1, "missed": 0, "recall": 1.0},
            "Exploits": {"support": 2, "detected": 0, "missed": 2, "recall": 0.0},
        })
        self.assertEqual(report["normal"], {"support": 3, "false_positives": 1, "false_positive_rate": 1 / 3})

    def test_overlap_counts_raw_vectors_and_retains_every_test_row(self):
        overlap = self.evaluate()["overlap"]
        expected = {
            "training_rows": 5,
            "test_rows": 7,
            "training_unique_vectors": 4,
            "test_unique_vectors": 6,
            "shared_vectors": 3,
            "shared_training_rows": 4,
            "shared_test_rows": 4,
        }
        self.assertEqual({name: overlap[name] for name in expected}, expected)
        self.assertEqual(overlap["shared_test"]["metrics"]["confusion_matrix"], [[1, 1], [1, 1]])
        self.assertEqual(overlap["unshared_test"]["metrics"]["confusion_matrix"], [[1, 0], [1, 1]])

    def test_scores_only_held_out_predictors_in_bounded_batches(self):
        fixture_bytes = [path.read_bytes() for path in (self.training_csv, self.test_csv)]
        self.evaluate()
        batches = [call.args[0] for call in self.pipeline.predict_proba.call_args_list]
        self.assertEqual([batch.shape for batch in batches], [(2, 42)] * 3 + [(1, 42)])
        self.assertEqual(np.concatenate(batches)[:, 0].tolist(), [1, 3, 2, 3, 4, 7, 8])
        self.assertEqual([path.read_bytes() for path in (self.training_csv, self.test_csv)], fixture_bytes)

    def frozen_fixture(self):
        artifact = self.root / "model"
        artifact.mkdir()
        payload = b"synthetic pinned model bytes"
        (artifact / "pipeline.pkl").write_bytes(payload)
        metadata = {
            "format_version": ARTIFACT_FORMAT_VERSION,
            "model_version": MODEL_VERSION,
            "feature_schema": feature_schema(),
            "decision_threshold": DECISION_THRESHOLD,
            "pipeline_sha256": sha256(payload).hexdigest(),
            "training": {"sha256": sha256(self.training_csv.read_bytes()).hexdigest()},
            "versions": runtime_versions(),
        }
        return artifact, metadata

    def cli_paths(self, artifact, metadata):
        return patch.multiple(
            evaluate_final,
            DEFAULT_ARTIFACT_DIR=artifact,
            TRAINING_CSV=self.training_csv,
            TEST_CSV=self.test_csv,
            FROZEN_PIPELINE_SHA256=metadata["pipeline_sha256"],
            FROZEN_TRAINING_SHA256=metadata["training"]["sha256"],
            FROZEN_TEST_SHA256=self.test_digest,
            EXPECTED_TRAINING_ROWS=5,
            EXPECTED_TEST_ROWS=7,
        )

    def test_cli_loads_the_frozen_model_and_reports_metrics(self):
        artifact, metadata = self.frozen_fixture()
        (artifact / "metadata.json").write_text(json.dumps(metadata), encoding="utf-8")
        output = io.StringIO()
        with self.cli_paths(artifact, metadata), redirect_stdout(output), patch.object(
            evaluate_final, "load_model", return_value=self.model
        ) as load:
            self.assertEqual(evaluate_final.main([]), 0)

        load.assert_called_once_with(artifact, expected_pipeline_sha256=metadata["pipeline_sha256"])
        report = json.loads(output.getvalue())
        self.assertEqual(report["decision_threshold"], DECISION_THRESHOLD)
        self.assertEqual(report["test_csv"]["sha256"], sha256(self.test_csv.read_bytes()).hexdigest())
        self.assertEqual(report["metrics"]["confusion_matrix"], [[2, 1], [2, 2]])

    def test_cli_rejects_a_same_shape_test_csv_with_an_unexpected_digest(self):
        artifact, metadata = self.frozen_fixture()
        (artifact / "metadata.json").write_text(json.dumps(metadata), encoding="utf-8")
        original = self.test_csv.read_bytes()
        changed = original.replace(b",101\r\n", b",201\r\n", 1)
        self.assertNotEqual(changed, original)
        self.assertEqual(len(changed), len(original))
        self.test_csv.write_bytes(changed)
        output, error = io.StringIO(), io.StringIO()
        with self.cli_paths(artifact, metadata), redirect_stdout(output), redirect_stderr(error), patch.object(
            evaluate_final, "load_model", return_value=self.model
        ):
            self.assertEqual(evaluate_final.main([]), 1)
        self.assertIn("Test CSV SHA-256 does not match the official G10 test partition", error.getvalue())
        self.assertEqual(output.getvalue(), "")
        self.pipeline.predict_proba.assert_not_called()

    def test_cli_scores_verified_bytes_even_if_the_test_path_changes_temporarily(self):
        artifact, metadata = self.frozen_fixture()
        (artifact / "metadata.json").write_text(json.dumps(metadata), encoding="utf-8")
        original = self.test_csv.read_bytes()
        alternate = original.replace(b",1,101\r\n", b",7,101\r\n", 1)
        self.assertNotEqual(alternate, original)
        read_csv = evaluate_final.read_prediction_csv
        score = self.pipeline.predict_proba.side_effect

        def replace_before_reading_training(path):
            if path == self.training_csv:
                self.test_csv.write_bytes(alternate)
            return read_csv(path)

        def restore_before_scoring(batch):
            self.test_csv.write_bytes(original)
            return score(batch)

        self.pipeline.predict_proba.side_effect = restore_before_scoring
        output = io.StringIO()
        with self.cli_paths(artifact, metadata), redirect_stdout(output), patch.object(
            evaluate_final, "load_model", return_value=self.model
        ), patch.object(evaluate_final, "read_prediction_csv", side_effect=replace_before_reading_training):
            self.assertEqual(evaluate_final.main([]), 0)

        self.assertEqual(json.loads(output.getvalue())["metrics"]["confusion_matrix"], [[2, 1], [2, 2]])

    def test_cli_rejects_freeze_mismatches_before_opening_held_out_data(self):
        artifact, metadata = self.frozen_fixture()
        manifest_path = artifact / "metadata.json"
        payload_path = artifact / "pipeline.pkl"
        original_open = Path.open
        original_payload = payload_path.read_bytes()
        original_training = self.training_csv.read_bytes()

        def guarded_open(path, *args, **kwargs):
            self.assertNotEqual(path, self.test_csv, "freeze checks must precede held-out file access")
            return original_open(path, *args, **kwargs)

        cases = {
            "model": ({**metadata, "model_version": "changed"}, original_payload, original_training),
            "schema": ({**metadata, "feature_schema": list(reversed(feature_schema()))},
                       original_payload, original_training),
            "threshold": ({**metadata, "decision_threshold": 0.6}, original_payload, original_training),
            "pipeline": (metadata, original_payload + b"changed", original_training),
            "training": (metadata, original_payload, original_training + b"changed"),
        }
        for case, (manifest, payload, training) in cases.items():
            with self.subTest(mismatch=case):
                manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
                payload_path.write_bytes(payload)
                self.training_csv.write_bytes(training)
                with self.cli_paths(artifact, metadata), redirect_stderr(io.StringIO()), patch.object(
                    Path, "open", new=guarded_open
                ), patch("ml.inference.pickle.loads") as deserialize:
                    self.assertNotEqual(evaluate_final.main([]), 0)
                deserialize.assert_not_called()
