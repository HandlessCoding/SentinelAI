"""Check the forest configuration, reproducibility, and split boundaries."""

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression

from ml.run_baseline import FOLD_COUNT, RANDOM_SEED, TrainingData, load_training
from ml.run_model_comparison import (
    FOREST,
    LOGISTIC,
    compare_models,
    comparison_pipelines,
    evaluate_forest_thresholds,
    fit_and_score,
    forest_pipeline,
)
from ml.run_threshold_analysis import INNER_FOLDS, checked_splits


def sample_training():
    """Build 18 groups with two identical predictor rows per group."""
    columns = ["dur", "proto", "service", "state", "is_ftp_login"]
    groups = np.repeat(np.arange(18), 2)
    predictors = np.array([
        [str(group), "tcp", "-" if group % 2 else "ftp", "FIN", str(group % 5)]
        for group in groups
    ])
    labels = groups % 2
    labels[0] = 1  # Retain a mixed-label group.
    return TrainingData(columns, predictors, labels, groups)


class ModelComparisonTests(unittest.TestCase):
    def test_builds_bounded_forest_and_original_logistic_pipeline(self):
        pipelines = comparison_pipelines(sample_training().columns)
        forest = pipelines[FOREST].named_steps["classifier"]
        logistic = pipelines[LOGISTIC].named_steps["classifier"]
        self.assertIsInstance(forest, RandomForestClassifier)
        self.assertEqual(forest.random_state, RANDOM_SEED)
        self.assertEqual(forest.n_jobs, 1)
        self.assertEqual(forest.n_estimators, 48)
        self.assertEqual(forest.max_depth, 14)
        self.assertEqual(forest.max_leaf_nodes, 512)
        self.assertIsInstance(logistic, LogisticRegression)
        self.assertEqual(logistic.solver, "liblinear")
        self.assertIn("preprocessor", pipelines[FOREST].named_steps)

    def test_scores_repeat_with_same_data_and_seed(self):
        data = sample_training()
        train = np.arange(24)
        validation = np.arange(24, 36)
        a, cost_a, _ = fit_and_score(
            forest_pipeline(data.columns), data, train, validation, measure_size=True
        )
        b, cost_b, _ = fit_and_score(
            forest_pipeline(data.columns), data, train, validation, measure_size=True
        )
        np.testing.assert_array_equal(a, b)
        self.assertGreater(cost_a["pipeline_bytes"], 0)
        self.assertEqual(cost_a["pipeline_bytes"], cost_b["pipeline_bytes"])

    def test_loader_excludes_metadata_and_preserves_categories(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "train.csv"
            path.write_text(
                "id,dur,proto,service,state,is_ftp_login,attack_cat,label\n"
                "1,1,tcp,-,FIN,2,Normal,0\n"
                "2,1,tcp,-,FIN,2,Fuzzers,1\n"
                "3,2,tcp,ftp,FIN,4,Fuzzers,1\n",
                encoding="utf-8",
            )
            data = load_training(path)
        self.assertEqual(data.columns, sample_training().columns)
        self.assertEqual(data.groups.tolist(), [0, 0, 1])
        self.assertEqual(data.labels.tolist(), [0, 1, 1])
        pipeline = forest_pipeline(data.columns)
        pipeline.fit(data.predictors, data.labels)
        encoder = pipeline.named_steps["preprocessor"].named_transformers_["categorical"]
        self.assertEqual(encoder.categories_[1].tolist(), ["-", "ftp"])
        self.assertEqual(encoder.categories_[3].tolist(), ["2", "4"])

    def test_models_receive_the_same_isolated_outer_partitions(self):
        data = sample_training()
        calls = []

        def audit(pipeline, fixture, train, validation, *, measure_size):
            self.assertFalse(set(fixture.groups[train]) & set(fixture.groups[validation]))
            self.assertTrue(measure_size)
            calls.append((train.copy(), validation.copy()))
            return fit_and_score(pipeline, fixture, train, validation, measure_size=measure_size)

        with patch("ml.run_model_comparison.fit_and_score", side_effect=audit):
            report = compare_models(data, allow_thresholds=False)
        self.assertEqual(len(calls), 2 * FOLD_COUNT)
        for i, fold in enumerate(report["folds"]):
            np.testing.assert_array_equal(calls[2 * i][0], calls[2 * i + 1][0])
            np.testing.assert_array_equal(calls[2 * i][1], calls[2 * i + 1][1])
            self.assertEqual(fold["overlapping_groups"], 0)
        np.testing.assert_array_equal(
            np.sort(np.concatenate([validation for _, validation in calls[::2]])),
            np.arange(len(data.labels)),
        )

    def test_threshold_fits_receive_only_outer_training_groups(self):
        data = sample_training()
        splits = list(checked_splits(data.labels, data.groups, FOLD_COUNT, RANDOM_SEED))
        calls = []

        def audit(pipeline, inner_data, train, validation):
            self.assertFalse(set(inner_data.groups[train]) & set(inner_data.groups[validation]))
            calls.append(set(inner_data.groups))
            return inner_data.labels[validation] * 0.8 + 0.1, {}, []

        outer_scores = data.labels * 0.7 + 0.15
        with patch("ml.run_model_comparison.fit_and_score", side_effect=audit):
            report = evaluate_forest_thresholds(data, splits, outer_scores)

        self.assertEqual(len(calls), FOLD_COUNT * INNER_FOLDS)
        for i, (train, _, _) in enumerate(splits):
            allowed = set(data.groups[train])
            self.assertEqual(calls[i * INNER_FOLDS:(i + 1) * INNER_FOLDS], [allowed] * INNER_FOLDS)
            point = report["folds"][i]["operating_points"]["5_percent"]
            self.assertAlmostEqual(point["threshold"], 0.9)
            self.assertEqual(point["metrics"]["recall"], 0)  # Outer attack score is 0.85.
            self.assertTrue(point["outer_budget_met"])
