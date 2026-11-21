"""Exercise the local package and inference contract using synthetic records."""

import csv
import json
from pathlib import Path
import shutil
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import numpy as np

from ml.inference import (
    ArtifactError,
    DECISION_THRESHOLD,
    FEATURE_TYPES,
    InputValidationError,
    MODEL_VERSION,
    feature_schema,
    load_model,
    read_prediction_csv,
    runtime_versions,
)
from ml.run_baseline import load_training
from ml.run_model_comparison import FOREST_PARAMS, forest_pipeline
from ml.train_model import train_and_package


def synthetic_record(number):
    record = dict.fromkeys(FEATURE_TYPES, "0")
    record.update({
        "dur": str(number / 10),
        "proto": "tcp" if number % 2 else "udp",
        "service": "ftp" if number % 2 else "-",
        "state": "FIN",
        "spkts": str(number + 1),
        "is_ftp_login": "4" if number % 2 else "2",
    })
    return record


class InferenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        cls.root = Path(temporary.name)
        cls.training_csv = cls.root / "training.csv"
        cls.records = [synthetic_record(number) for number in range(40)]
        with cls.training_csv.open("w", encoding="utf-8", newline="") as file:
            writer = csv.DictWriter(file, ["id", *FEATURE_TYPES, "attack_cat", "label"])
            writer.writeheader()
            for number, record in enumerate(cls.records):
                writer.writerow({
                    **record, "id": number + 1,
                    "attack_cat": "Generic" if number % 2 else "Normal",
                    "label": number % 2,
                })
        cls.package = cls.root / MODEL_VERSION
        train_and_package(cls.training_csv, cls.package)
        cls.model = load_model(cls.package)

    def test_package_records_metadata_and_matches_fresh_g4_predictions(self):
        manifest = json.loads((self.package / "metadata.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["model_version"], MODEL_VERSION)
        self.assertEqual(manifest["model_type"], "RandomForestClassifier")
        self.assertEqual(manifest["feature_schema"], feature_schema())
        self.assertEqual(manifest["versions"], runtime_versions())
        self.assertEqual(manifest["training"]["rows"], len(self.records))
        self.assertEqual(manifest["decision_threshold"], DECISION_THRESHOLD)
        for name, expected in FOREST_PARAMS.items():
            self.assertEqual(manifest["training"]["parameters"][name], expected)

        data = load_training(self.training_csv)
        reference = forest_pipeline(data.columns).fit(data.predictors, data.labels)
        expected = reference.predict_proba(data.predictors)[:, 1]
        actual = self.model.predict(self.records)
        np.testing.assert_array_equal([item["attack_probability"] for item in actual], expected)
        for result, attack_probability in zip(actual, expected):
            label = int(attack_probability > 0.5)
            self.assertEqual(result["label"], label)
            self.assertEqual(result["classification"], ("normal", "attack")[label])

    def test_repackaging_same_data_reproduces_scores(self):
        with TemporaryDirectory(dir=self.root) as new_root:
            new_package = Path(new_root) / MODEL_VERSION
            train_and_package(self.training_csv, new_package)
            self.assertEqual(load_model(new_package).predict(self.records), self.model.predict(self.records))

    def test_existing_package_is_preserved_without_retraining(self):
        with patch("ml.train_model.load_training") as load:
            with self.assertRaisesRegex(FileExistsError, "already exists"):
                train_and_package(self.training_csv, self.package)
        load.assert_not_called()
        self.assertTrue((self.package / "pipeline.pkl").is_file())

    def test_inference_never_fits_and_accepts_reordered_columns_and_optional_metadata(self):
        reordered = dict(reversed(list(self.records[1].items())))
        reordered.update({"id": 10, "label": 0, "attack_cat": "Normal"})
        reordered.update({"dur": 0.1, "spkts": 2, "is_ftp_login": 4})
        with patch("sklearn.pipeline.Pipeline.fit", side_effect=AssertionError("unexpected fit")):
            current = load_model(self.package)
            self.assertEqual(current.predict([reordered]), current.predict([self.records[1]]))

    def test_default_threshold_includes_ties_in_normal(self):
        with patch.object(
            self.model._pipeline, "predict_proba", return_value=np.array([[0.5, 0.5], [0.499, 0.501]])
        ):
            self.assertEqual([row["label"] for row in self.model.predict(self.records[:2])], [0, 1])

    def test_invalid_records_fail_before_scoring_any_row(self):
        record = self.records[0]
        missing_service = {name: value for name, value in record.items() if name != "service"}
        cases = [
            (missing_service, "missing columns: service"),
            ({**record, "unknown": 0}, "unexpected columns: unknown"),
            ({**record, "service": " "}, "field 'service': value is missing"),
            ({**record, "sbytes": None}, "field 'sbytes': value is missing"),
            ({**record, "proto": 6}, "field 'proto': expected text"),
            ({**record, "spkts": "1.5"}, "field 'spkts': expected an integer"),
            ({**record, "is_ftp_login": True}, "Booleans"),
            ({**record, "dur": float("nan")}, "finite number"),
            ({**record, "dur": "1e999"}, "finite number"),
            ([], "Record 2 must be a mapping"),
        ]
        with patch.object(self.model._pipeline, "predict_proba") as score:
            for invalid, message in cases:
                with self.subTest(message=message):
                    with self.assertRaisesRegex(InputValidationError, message):
                        self.model.predict([record, invalid])
            for batch in (None, []):
                with self.assertRaises(InputValidationError):
                    self.model.predict(batch)
            score.assert_not_called()

    def test_csv_validates_header_and_record_structure(self):
        with TemporaryDirectory(dir=self.root) as directory:
            path = Path(directory) / "input.csv"
            header = ",".join(FEATURE_TYPES)
            examples = [
                (f"{header},dur\n", "duplicate column names"),
                (f"{header}\n1,2\n", "expected 42"),
                (f'{header}\n"unterminated\n', "Invalid CSV"),
            ]
            for data, message in examples:
                with self.subTest(message=message):
                    path.write_text(data, encoding="utf-8")
                    with self.assertRaisesRegex(InputValidationError, message):
                        list(read_prediction_csv(path))

    def test_incompatible_metadata_and_corrupt_payload_are_rejected_before_pickle(self):
        with TemporaryDirectory(dir=self.root) as directory:
            copied = Path(directory) / MODEL_VERSION
            shutil.copytree(self.package, copied)
            manifest = copied / "metadata.json"
            original = manifest.read_text(encoding="utf-8")
            incompatible = json.loads(original)
            incompatible["versions"]["scikit-learn"] = "0.0.0"
            manifest.write_text(json.dumps(incompatible), encoding="utf-8")
            with patch("ml.inference.pickle.loads") as deserialize:
                with self.assertRaisesRegex(ArtifactError, "runtime versions"):
                    load_model(copied)
                manifest.write_text(original, encoding="utf-8")
                (copied / "pipeline.pkl").write_bytes(b"corrupt artifact")
                with self.assertRaisesRegex(ArtifactError, "digest"):
                    load_model(copied)
                deserialize.assert_not_called()
