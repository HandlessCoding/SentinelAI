"""Check split integrity, calibrated decisions, and the one-time final gate."""

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch

import numpy as np
from threadpoolctl import threadpool_limits

from ml.run_baseline import CATEGORICAL_COLUMNS, TrainingData
from ml.run_unsw_development import (
    BOOSTED, candidate_pipelines, evaluate_frozen, load_pinned_training, run_experiment,
    score_report, select_candidate, select_recall_threshold, write_report,
)
from ml.unsw_development_split import audit_partitions, development_partitions, group_statistics, normalize_predictors


def synthetic_data():
    columns = [*CATEGORICAL_COLUMNS, "dur"]
    rows = [["tcp", "-", "FIN", "2", str(index)] for index in range(120)]
    rows.append(["tcp", "-", "FIN", "2", "1.0"])
    rows.append(["tcp", "-", "FIN", "4", "1"])
    labels = np.array([index % 2 for index in range(122)])
    return TrainingData(columns, np.asarray(rows, dtype=object), labels, np.arange(len(rows)))


class UNSWDevelopmentTests(unittest.TestCase):
    def test_equivalent_numeric_spellings_group_without_merging_categories(self):
        data = normalize_predictors(synthetic_data())
        self.assertEqual(data.groups[1], data.groups[120])
        self.assertNotEqual(data.groups[1], data.groups[121])
        self.assertEqual(data.predictors[121, 3], "4")
        self.assertEqual(data.predictors[121, 1], "-")
        conflicts = group_statistics(data.labels, data.groups)
        self.assertEqual(conflicts["conflicting_groups"], 1)
        self.assertEqual(conflicts["rows_in_conflicting_groups"], 2)
        self.assertEqual(conflicts["minimum_errors_from_conflicts"], 1)

    def test_four_roles_are_deterministic_and_isolate_group_members(self):
        raw = synthetic_data()
        data = normalize_predictors(raw)
        roles = development_partitions(data.labels, data.groups)
        repeated = development_partitions(data.labels, data.groups)
        for name in roles:
            np.testing.assert_array_equal(roles[name], repeated[name])
        report = audit_partitions(data.labels, raw.groups, data.groups, roles)
        self.assertFalse(any(any(pair.values()) for pair in report["overlapping_groups"].values()))
        self.assertEqual(sum(role["rows"] for role in report["roles"].values()), len(data.labels))
        group_role = next(role for role, indices in roles.items() if 1 in indices)
        self.assertIn(120, roles[group_role])
        target = "calibration" if group_role != "calibration" else "comparison"
        roles[group_role] = roles[group_role][roles[group_role] != 120]
        roles[target] = np.append(roles[target], 120)
        contaminated = audit_partitions(data.labels, raw.groups, data.groups, roles)
        self.assertTrue(any("share predictor groups" in error for error in contaminated["blockers"]))

    def test_insufficient_class_gate_prevents_training(self):
        raw = synthetic_data()
        data = normalize_predictors(raw)
        with TemporaryDirectory() as folder:
            output = Path(folder) / "run"
            with patch("ml.run_unsw_development.load_pinned_training", return_value=(data, raw.groups)), patch(
                "ml.run_unsw_development.train_candidates"
            ) as train, self.assertRaisesRegex(ValueError, "Split gates failed"):
                run_experiment(Path("unused"), output)
            self.assertTrue((output / "split-audit.json").exists())
            self.assertFalse((output / "final-started.json").exists())
            train.assert_not_called()

    def test_inclusive_score_ties_and_minimum_recall(self):
        labels = np.array([1] * 20 + [0] * 3)
        scores = np.array([0.9] * 18 + [0.7, 0.1, 0.75, 0.7, 0.4])
        threshold = select_recall_threshold(labels, scores)
        self.assertEqual(threshold, 0.7)
        result = score_report(labels, scores, threshold)["calibrated"]
        self.assertEqual(result["confusion_matrix"], [[1, 2], [1, 19]])
        self.assertAlmostEqual(result["recall"], 0.95)
        self.assertAlmostEqual(result["false_positive_rate"], 2 / 3)

    def test_candidate_order_uses_comparison_points_without_relaxing_thresholds(self):
        def candidate(recall, fpr):
            return {"comparison": {"calibrated": {"recall": recall, "false_positive_rate": fpr}}}

        pool = {"below": candidate(0.949, 0.01), "passes": candidate(0.95, 0.08), "other": candidate(0.97, 0.10)}
        self.assertEqual(select_candidate(pool), ("passes", True))
        self.assertEqual(select_candidate({"closest": pool["below"], "other": candidate(0.94, 0.001)}),
                         ("closest", False))

    def test_candidate_preprocessing_fits_training_categories_and_handles_unseen_values(self):
        data = normalize_predictors(synthetic_data())
        holdout = data.predictors[114:].copy()
        holdout[:, 0] = "new-protocol"
        with threadpool_limits(limits=1):
            for name, pipeline in candidate_pipelines(data.columns).items():
                with self.subTest(candidate=name):
                    pipeline.fit(data.predictors[:114], data.labels[:114])
                    categories = pipeline.named_steps["preprocessor"].named_transformers_["categorical"].categories_
                    self.assertEqual(categories[0].tolist(), ["tcp"])
                    self.assertEqual(categories[1].tolist(), ["-"])
                    self.assertTrue(np.isfinite(pipeline.predict_proba(holdout)).all())
                    if name == BOOSTED:
                        self.assertFalse(pipeline.named_steps["classifier"].early_stopping)

    def test_final_scoring_has_an_exclusive_start_marker(self):
        with TemporaryDirectory() as directory:
            output = Path(directory)
            write_report(output / "selection.json", {"selected": "synthetic-fixture"})
            samples = (np.array([[1], [2]]), np.array([0, 1]))
            pipeline = Mock()
            pipeline.predict_proba.return_value = np.array([[0.9, 0.1], [0.2, 0.8]])
            self.assertEqual(evaluate_frozen(output, pipeline, 0.8, samples)["calibrated"]["accuracy"], 1.0)
            with self.assertRaises(FileExistsError):
                evaluate_frozen(output, pipeline, 0.8, samples)
            pipeline.predict_proba.assert_called_once()

    def test_non_training_filename_is_rejected_before_open(self):
        with patch("ml.run_unsw_development.sha256_file") as digest, self.assertRaisesRegex(ValueError, "pinned"):
            load_pinned_training(Path("synthetic-fixture.csv"))
        digest.assert_not_called()
