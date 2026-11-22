"""Check G32.2 novelty, fit/calibration isolation, and checkpoint safeguards."""

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch

import numpy as np

from ml.run_baseline import TrainingData
from ml.run_unsw_extended import Halt, run_job
from ml.unsw_extended_design import DISCOVERY_SEEDS, candidates, study_splits, synthetic_smoke_data
from ml.unsw_extended_metrics import decisions, fit_rotation, rank_metrics
from ml.unsw_overnight_models import configurations


class ExtendedStudyTests(unittest.TestCase):
    def test_plan_has_unique_new_profiles_and_pairs(self):
        def fingerprint(row):
            return row["family"], row["feature_set"], json.dumps(row["parameters"], sort_keys=True)

        plan = candidates()
        fingerprints = {fingerprint(row) for row in plan}
        self.assertEqual(len(plan), 184)
        self.assertEqual(len(fingerprints), len(plan))
        self.assertFalse(fingerprints.intersection(map(fingerprint, configurations())))
        for recipe in {row["recipe"] for row in plan}:
            self.assertTrue({"full", "no_ttl"} <= {row["feature_set"] for row in plan if row["recipe"] == recipe})

    def test_challenge_is_physically_absent_from_discovery_and_all_roles_are_grouped(self):
        data = synthetic_smoke_data()
        data.predictors[1] = data.predictors[0].copy()
        data.predictors[1, data.columns.index("sttl")] = 128.0
        data.predictors[1, data.columns.index("ct_srv_dst")] = 117.0
        discovery, rotations, challenge, audit = study_splits(data, smoke=True)
        self.assertEqual(len(discovery.labels) + len(challenge["evaluation"]), len(data.labels))
        duration = data.columns.index("dur")
        locked = data.predictors[challenge["evaluation"], duration]
        self.assertFalse(np.intersect1d(locked, discovery.predictors[:, duration]).size)
        role_for_first = next(role for role, indices in challenge.items() if 0 in indices)
        self.assertIn(1, challenge[role_for_first])
        for seed in DISCOVERY_SEEDS:
            self.assertEqual(len(rotations[seed]), 5)
            for fold in audit["rotations"][str(seed)]:
                self.assertFalse(any(any(pair.values()) for pair in fold["overlapping_groups"].values()))

    def test_probability_fit_gets_only_probability_role_labels_and_threshold_uses_separate_labels(self):
        probability_scores, probability_labels = np.array([0.1, 0.3, 0.6, 0.9]), np.array([0, 1, 0, 1])
        threshold_scores, threshold_labels = np.array([0.1, 0.2, 0.6, 0.6]), np.array([0, 0, 1, 1])
        with patch("ml.unsw_extended_metrics.fit_probability_map", return_value=lambda scores: scores) as mapper:
            _, learned = decisions(probability_scores, probability_labels, threshold_scores, threshold_labels, ("sigmoid-r965",))
        method, scores, labels = mapper.call_args.args
        self.assertEqual(method, "sigmoid")
        np.testing.assert_array_equal(scores, probability_scores)
        np.testing.assert_array_equal(labels, probability_labels)
        self.assertEqual(learned["sigmoid-r965"]["threshold"], 0.6)
        self.assertEqual(learned["sigmoid-r965"]["threshold_confusion"], [[2, 0], [0, 2]])

    def test_rotation_locks_threshold_before_prediction_on_evaluation(self):
        template = synthetic_smoke_data()
        rows = template.predictors[:24].copy()
        rows[:, 0] = np.arange(len(rows))
        data = TrainingData(template.columns, rows, np.arange(len(rows)) % 2, np.arange(len(rows)))
        roles = {role: np.arange(i, i + 6) for i, role in zip(range(0, 24, 6),
                 ("fit", "probability", "threshold", "evaluation"), strict=True)}
        calls = []

        def predict(predictors):
            numbers = np.asarray(predictors[:, 0], dtype=float)
            calls.append(numbers.tolist())
            probability = numbers / 24
            return np.column_stack((1 - probability, probability))

        model = Mock()
        model.predict_proba.side_effect = predict

        def freeze(locked):
            self.assertEqual(calls, [roles["probability"].tolist(), roles["threshold"].tolist()])
            self.assertIn("raw-r95", locked)

        with patch("ml.unsw_extended_metrics.make_pipeline", return_value=model):
            result = fit_rotation(candidates()[0], data, roles, 42, 1, lambda: None, policies=("raw-r95",), freeze=freeze)
        self.assertEqual(calls[-1], roles["evaluation"].tolist())
        np.testing.assert_array_equal(model.fit.call_args.args[0][:, 0], roles["fit"])
        cells = result["policies"]["raw-r95"]["metrics"]["confusion_matrix"]
        self.assertEqual(sum(map(sum, cells)), len(roles["evaluation"]))

    def test_rank_prefers_worst_fold_recall_floor_over_lower_false_positives(self):
        stable = {"recall": {"min": 0.95}, "false_positive_rate": {"mean": 0.049, "max": 0.057}}
        unstable = {"recall": {"min": 0.94}, "false_positive_rate": {"mean": 0.01, "max": 0.02}}
        self.assertLess(rank_metrics(stable), rank_metrics(unstable))

    def test_discovery_resumes_saved_folds_and_challenge_never_replays_after_access_marker(self):
        config = candidates()[0]
        fold = {"fold": 1, "policies": {"raw-r95": {"metrics": {
            "accuracy": 0.95, "balanced_accuracy": 0.95, "precision": 0.95, "recall": 0.95, "false_positive_rate": 0.05,
        }}}}
        with TemporaryDirectory() as location:
            root = Path(location)
            (root / "checkpoints").mkdir()
            with patch("ml.run_unsw_extended.fit_rotation", side_effect=[fold, Halt("stop")]):
                with self.assertRaises(Halt):
                    run_job(root, "discovery", config, None, [{}, {}], 7, ("raw-r95",), {}, lambda: None)
            with patch("ml.run_unsw_extended.fit_rotation", return_value={**fold, "fold": 2}) as fit:
                completed = run_job(root, "discovery", config, None, [{}, {}], 7, ("raw-r95",), {}, lambda: None)
                self.assertEqual(completed["status"], "completed")
                self.assertEqual(fit.call_args.args[4], 2)
                run_job(root, "discovery", config, None, [{}, {}], 7, ("raw-r95",), {}, lambda: None)
                fit.assert_called_once()
            (root / f"challenge-started-{config['id']}.json").write_text("{}")
            with patch("ml.run_unsw_extended.fit_rotation") as fit:
                blocked = run_job(root, "challenge", config, None, [{}], 8, ("raw-r95",), {}, lambda: None)
                self.assertEqual(blocked["status"], "unavailable")
                fit.assert_not_called()
