"""Test operating-point selection and isolation in the nested experiment."""

import unittest
from unittest.mock import patch

import numpy as np

from ml.run_baseline import FOLD_COUNT, RANDOM_SEED, TrainingData, build_pipeline
from ml.run_threshold_analysis import (
    INNER_FOLDS,
    checked_splits,
    fit_attack_scores,
    nested_evaluation,
    select_threshold,
)


def mixed_label_groups():
    """Return 18 groups with both labels and identical predictors per group."""
    columns = ["dur", "proto", "service", "state", "is_ftp_login"]
    groups = np.repeat(np.arange(18), 2)
    predictors = np.array([[str(group), "tcp", "-", "FIN", "2"] for group in groups])
    return TrainingData(columns, predictors, np.tile([0, 1], 18), groups)


class ThresholdTests(unittest.TestCase):
    def test_maximizes_recall_under_each_budget(self):
        labels = [0] * 20 + [1] * 4
        scores = np.r_[np.linspace(0.1, 0.7, 20), [0.99, 0.69, 0.66, 0.2]]
        for budget, threshold, recall in [(0.05, 0.69, 0.5), (0.10, 0.66, 0.75)]:
            with self.subTest(budget=budget):
                choice = select_threshold(labels, scores, budget)
                self.assertAlmostEqual(choice["threshold"], threshold)
                self.assertAlmostEqual(choice["inner_recall"], recall)
                self.assertAlmostEqual(choice["inner_false_positive_rate"], budget)

    def test_equal_recall_prefers_lower_fpr_and_higher_threshold(self):
        choice = select_threshold([1, 0, 0, 1], [0.95, 0.9, 0.8, 0.7], 0.5)
        self.assertEqual(choice["threshold"], 0.95)
        self.assertEqual(choice["inner_false_positive_rate"], 0)

    def test_ties_cannot_be_split_to_claim_a_finite_feasible_threshold(self):
        labels = [0, 1, 0, 1]
        scores = [0.9, 0.9, 0.3, 0.7]
        self.assertIsNone(select_threshold(labels, scores, 0.10))
        choice = select_threshold(labels, scores, 0.5)
        self.assertEqual(choice["threshold"], 0.7)
        self.assertEqual(choice["inner_recall"], 1)
        self.assertEqual(choice["inner_false_positive_rate"], 0.5)

    def test_group_overlap_fails_before_fit(self):
        data = mixed_label_groups()
        with patch("ml.run_threshold_analysis.StratifiedGroupKFold") as splitter:
            splitter.return_value.split.return_value = [(np.array([0]), np.array([1]))]
            with self.assertRaisesRegex(RuntimeError, "shares 1 raw predictor groups"):
                list(checked_splits(data.labels, data.groups, FOLD_COUNT, RANDOM_SEED))

    def test_fit_learns_preprocessing_only_from_its_training_rows(self):
        columns = ["dur", "proto", "service", "state", "is_ftp_login"]
        data = TrainingData(
            columns,
            np.array([["0", "tcp", "-", "FIN", "2"], ["2", "udp", "ftp", "FIN", "4"],
                      ["1000", "unseen", "unseen", "UNSEEN", "9"]]),
            np.array([0, 1, 1]),
            np.arange(3),
        )
        fitted = []

        def remember_pipeline(columns, model):
            pipeline = build_pipeline(columns, model)
            fitted.append(pipeline)
            return pipeline

        with patch("ml.run_threshold_analysis.build_pipeline", side_effect=remember_pipeline):
            scores, warnings = fit_attack_scores(data, np.array([0, 1]), np.array([2]))
        preprocessor = fitted[0].named_steps["preprocessor"]
        self.assertEqual(preprocessor.named_transformers_["numeric"].mean_.tolist(), [1.0])
        self.assertEqual(
            [values.tolist() for values in preprocessor.named_transformers_["categorical"].categories_],
            [["tcp", "udp"], ["-", "ftp"], ["FIN"], ["2", "4"]],
        )
        self.assertEqual(scores.shape, (1,))
        self.assertEqual(warnings, [])

    def test_inner_predictions_and_labels_are_isolated_from_outer_validation(self):
        data = mixed_label_groups()
        expected_splits = list(checked_splits(data.labels, data.groups, FOLD_COUNT, RANDOM_SEED))
        events = []

        def score(data, train, validation):
            events.append(("fit", train.copy(), validation.copy()))
            self.assertFalse(set(data.groups[train]) & set(data.groups[validation]))
            return data.groups[validation] / 18, []

        def select(labels, scores, budget):
            events.append(("select", labels.copy(), scores.copy()))
            return select_threshold(labels, scores, budget)

        with patch("ml.run_threshold_analysis.fit_attack_scores", side_effect=score), patch(
            "ml.run_threshold_analysis.select_threshold", side_effect=select
        ):
            report, probabilities = nested_evaluation(data)

        block_size = INNER_FOLDS + 3  # three fits, two selections, one outer fit
        self.assertEqual(len(events), FOLD_COUNT * block_size)
        for fold, (outer_train, outer_validation, _) in zip(report["folds"], expected_splits):
            start = (fold["fold"] - 1) * block_size
            inner_fits = events[start:start + INNER_FOLDS]
            for event, fit_rows, validation_rows in inner_fits:
                self.assertEqual(event, "fit")
                np.testing.assert_array_equal(np.sort(np.r_[fit_rows, validation_rows]), outer_train)
            np.testing.assert_array_equal(
                np.sort(np.concatenate([validation for _, _, validation in inner_fits])), outer_train
            )
            for event, labels, scores in events[start + INNER_FOLDS:start + block_size - 1]:
                self.assertEqual(event, "select")
                np.testing.assert_array_equal(labels, data.labels[outer_train])
                np.testing.assert_array_equal(scores, data.groups[outer_train] / 18)
            event, train, validation = events[start + block_size - 1]
            self.assertEqual(event, "fit")
            np.testing.assert_array_equal(train, outer_train)
            np.testing.assert_array_equal(validation, outer_validation)
            self.assertEqual(fold["overlapping_groups"], 0)
            self.assertTrue(all(split["overlapping_groups"] == 0 for split in fold["inner_folds"]))
        np.testing.assert_array_equal(probabilities, data.groups / 18)
        self.assertEqual(report["classes"], {"normal": 18, "attack": 18})

    def test_unavailable_policy_is_reported_without_outer_metrics(self):
        def tied_scores(data, train, validation):
            return np.full(len(validation), 0.5), []

        with patch("ml.run_threshold_analysis.fit_attack_scores", side_effect=tied_scores):
            report, _ = nested_evaluation(mixed_label_groups())
        for fold in report["folds"]:
            for name in ("5_percent", "10_percent"):
                point = fold["operating_points"][name]
                self.assertIsNone(point["threshold"])
                self.assertIsNone(point["metrics"])
                self.assertIn("No finite threshold", point["status"])
        self.assertEqual(report["pooled"]["default"]["metrics"]["recall"], 0.0)
        self.assertEqual(report["pooled"]["5_percent"]["folds_with_threshold"], 0)
        self.assertIsNone(report["pooled"]["5_percent"]["metrics"])
