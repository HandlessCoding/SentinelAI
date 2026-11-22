import tempfile
import unittest
from pathlib import Path

import numpy as np

from ml.audit_unsw_qualification import discovery_categories, feature_group_errors, reliability, replay_candidate
from ml.verify_unsw_research import verify_matrix, verify_metrics


class QualificationAuditTests(unittest.TestCase):
    def test_rejects_inconsistent_saved_metrics_and_class_counts(self):
        counts = {"normal": 10, "attack": 10}
        metrics = {
            "confusion_matrix": [[8, 2], [1, 9]], "recall": 0.9, "false_positive_rate": 0.2,
            "accuracy": 0.85, "precision": 9 / 11, "balanced_accuracy": 0.85, "f1": 18 / 21,
        }
        verify_metrics(metrics, counts)
        with self.assertRaisesRegex(ValueError, "metrics"):
            verify_metrics({**metrics, "recall": 0.95}, counts)
        with self.assertRaisesRegex(ValueError, "coverage"):
            verify_matrix(metrics["confusion_matrix"], {"normal": 9, "attack": 10})
        with self.assertRaisesRegex(ValueError, "count"):
            verify_matrix([[8.0, 2], [1, 9]], counts)

    def test_group_errors_keep_conflicting_vectors_and_their_minimum_errors(self):
        result = feature_group_errors(
            np.array([0, 1, 1, 0, 0, 1]),
            np.array([True, True, True, False, False, False]),
            np.array(["mixed", "mixed", "mixed", "normal", "normal", "single"]),
        )
        self.assertEqual(result["conflicting"], {
            "groups": 1, "confusion_matrix": [[0, 1], [0, 2]], "minimum_errors_from_exact_conflicts": 1,
        })
        self.assertEqual(result["repeated_single_label"]["confusion_matrix"], [[2, 0], [0, 0]])
        self.assertEqual(result["singleton"]["confusion_matrix"], [[0, 0], [1, 0]])

    def test_calibration_includes_score_one_and_rejects_nonfinite_values(self):
        labels = np.array([0, 1, 1])
        result = reliability(labels, np.array([0, 0.95, 1.0]))
        self.assertEqual([row["rows"] for row in result["bins"]], [1, 2])
        self.assertAlmostEqual(result["brier"], 0.05 ** 2 / 3)
        self.assertAlmostEqual(result["ece_10_equal_width"], 0.05 / 3)
        with self.assertRaisesRegex(ValueError, "calibration"):
            reliability(labels, np.array([0, np.nan, 1.0]))

    def test_replay_refuses_a_challenge_job(self):
        checkpoint = {"identity": {"stage": "challenge"}}
        with self.assertRaisesRegex(ValueError, "only the original discovery"):
            replay_candidate(None, None, None, None, checkpoint, "isotonic-r95")

    def test_category_lookup_keeps_only_discovery_indices_and_checks_alignment(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "fixture.csv"
            path.write_text("attack_cat,label\nNormal,0\nHidden,1\n Fuzzers ,1\n", encoding="utf-8")
            result = discovery_categories(path, np.array([0, 2]), np.array([0, 1]))
            self.assertEqual(result.tolist(), ["Normal", "Fuzzers"])
            with self.assertRaisesRegex(ValueError, "do not match"):
                discovery_categories(path, np.array([0, 2]), np.array([1, 1]))
