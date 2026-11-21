"""Test the baseline's feature selection, fold isolation, and reporting."""

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import numpy as np
from sklearn.dummy import DummyClassifier

from ml.run_baseline import (
    TrainingData,
    binary_metrics,
    build_pipeline,
    load_training,
    run_baseline,
)


class BaselineTests(unittest.TestCase):
    def test_loader_excludes_metadata_and_groups_exact_raw_predictors(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "training.csv"
            path.write_text(
                "id,dur,proto,service,state,is_ftp_login,attack_cat,label\n"
                "1,1,tcp,-,FIN,2,Normal,0\n"
                "2,1,tcp,-,FIN,2,Fuzzers,1\n"
                "3,1.0,tcp,-,FIN,2,Normal,0\n"
                "4,1,tcp,ftp,FIN,4,Fuzzers,1\n",
                encoding="utf-8",
            )
            data = load_training(path)

        self.assertEqual(data.columns, ["dur", "proto", "service", "state", "is_ftp_login"])
        self.assertEqual(data.labels.tolist(), [0, 1, 0, 1])
        self.assertEqual(data.groups.tolist(), [0, 0, 1, 2])
        self.assertEqual(data.predictors[0].tolist(), ["1", "tcp", "-", "FIN", "2"])
        self.assertEqual(data.predictors[3, -1], "4")

    def test_pipeline_learns_scaling_and_categories_from_fit_rows(self):
        columns = ["dur", "proto", "service", "state", "is_ftp_login"]
        x_train = np.array([["0", "tcp", "-", "FIN", "2"], ["2", "udp", "ftp", "INT", "4"]])
        x_validation = np.array([["3", "unseen", "-", "FIN", "4"]])
        pipeline = build_pipeline(columns, DummyClassifier(strategy="most_frequent"))
        pipeline.fit(x_train, [0, 1])
        preprocessor = pipeline.named_steps["preprocessor"]
        encoder = preprocessor.named_transformers_["categorical"]
        scaler = preprocessor.named_transformers_["numeric"]

        self.assertEqual(
            [categories.tolist() for categories in encoder.categories_],
            [["tcp", "udp"], ["-", "ftp"], ["FIN", "INT"], ["2", "4"]],
        )
        np.testing.assert_allclose(scaler.mean_, [1])
        np.testing.assert_allclose(preprocessor.transform(x_validation), [[0, 0, 1, 0, 1, 0, 0, 1, 2]])

    def test_three_folds_keep_conflicting_rows_and_isolate_groups(self):
        columns = ["dur", "proto", "service", "state", "is_ftp_login"]
        data = TrainingData(
            columns,
            np.array([[str(group), "tcp", "-", "FIN", "0"] for group in range(9) for _ in range(2)]),
            np.tile([0, 1], 9),
            np.repeat(np.arange(9), 2),
        )
        report = run_baseline(data)
        self.assertEqual(report["classes"], {"normal": 9, "attack": 9})
        self.assertEqual(report["distinct_groups"], 9)
        self.assertEqual(len(report["folds"]), 3)
        for fold in report["folds"]:
            self.assertEqual(fold["overlapping_groups"], 0)
            self.assertEqual(fold["validation_classes"], {"normal": 3, "attack": 3})
            self.assertEqual(fold["validation_groups"], 3)
            self.assertEqual(fold["train_groups"], 6)
            self.assertEqual(set(fold["models"]), {"dummy", "logistic_regression"})
        self.assertEqual(report["summary"]["dummy"]["balanced_accuracy"], {"mean": 0.5, "std": 0.0})

        with patch("ml.run_baseline.StratifiedGroupKFold") as splitter:
            splitter.return_value.split.return_value = [(np.array([0]), np.array([1]))]
            with self.assertRaisesRegex(RuntimeError, "shares 1 predictor groups"):
                run_baseline(data)

    def test_metrics_use_attack_as_positive(self):
        actual = [0] * 4 + [1] * 6
        predicted = [0, 0, 0, 1] + [0, 0, 1, 1, 1, 1]
        metrics = binary_metrics(actual, predicted)
        self.assertEqual(metrics["confusion_matrix"], [[3, 1], [2, 4]])
        self.assertAlmostEqual(metrics["accuracy"], 0.7)
        self.assertAlmostEqual(metrics["balanced_accuracy"], (3 / 4 + 4 / 6) / 2)
        self.assertAlmostEqual(metrics["precision"], 0.8)
        self.assertAlmostEqual(metrics["recall"], 4 / 6)
        self.assertAlmostEqual(metrics["f1"], 8 / 11)
        self.assertAlmostEqual(metrics["false_positive_rate"], 0.25)
        self.assertEqual(binary_metrics([0, 1], [0, 0])["precision"], 0)
