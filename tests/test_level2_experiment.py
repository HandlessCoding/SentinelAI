"""Synthetic checks for the Level 2 development experiment."""

import unittest

import numpy as np

from ml.run_level2_experiment import (
    ambiguous_mask, build_model, connected_groups, exported_tuple, feasibility, fold_design,
    subgroup_metrics,
)


class Level2ExperimentTests(unittest.TestCase):
    def test_tuple_preserves_endpoint_pairs_and_ignores_direction(self):
        first = ["192.0.2.11", "0100", "198.51.100.12", "443"]
        reverse = ["198.51.100.12", "443", "192.0.2.11", "100"]
        offsets = range(4)
        self.assertEqual(exported_tuple(first, offsets, 6), exported_tuple(reverse, offsets, 6))
        self.assertNotEqual(exported_tuple(first, offsets, 6), exported_tuple(reverse, offsets, 17))

    def test_graph_connects_transitive_tuple_and_vector_edges(self):
        groups = connected_groups([b"a", b"a", b"b", b"c", b"d"], [1, 2, 2, 3, 3])
        self.assertEqual(groups[0], groups[1])
        self.assertEqual(groups[0], groups[2])
        self.assertEqual(groups[3], groups[4])
        self.assertNotEqual(groups[0], groups[3])

    def test_oversized_component_can_make_class_support_impossible(self):
        labels = np.array([0] * 5 + [1] * 2 + [0] + [1] * 2)
        result, folds = feasibility(labels, np.array([0] * 7 + [1, 2, 3]))
        self.assertFalse(result["row_feasible"])
        self.assertEqual(result["largest"], {"rows": 7, "attack": 2, "normal": 5})
        self.assertIn("remaining components cannot meet normal support", result["reasons"])
        self.assertEqual(folds, [])

    def test_fit_calibration_and_validation_use_disjoint_exact_vectors(self):
        groups = np.repeat(np.arange(90), 2)
        labels = np.tile([0, 1], 90)
        vectors = [int(group).to_bytes(2, "big") for group in groups]
        plans = fold_design(labels, groups, [("shared",)] * len(labels), vectors)
        self.assertEqual(sum(len(val) for _, _, val, _ in plans), len(labels))
        for fit, cal, val, audit in plans:
            self.assertFalse(set(groups[fit]) & set(groups[cal]))
            self.assertFalse(set(groups[np.r_[fit, cal]]) & set(groups[val]))
            self.assertEqual(audit["shared_exported_tuples"], 1)

    def test_subgroups_count_only_attack_rows_for_category_recall(self):
        labels = np.array([0, 1, 1, 0])
        predicted = np.array([0, 1, 0, 1])
        categories = np.array(["benign", "xss", "xss", "benign"])
        ambiguous = ambiguous_mask([b"a", b"a", b"b", b"c"], labels)
        scores = subgroup_metrics(labels, categories, predicted, ambiguous)
        self.assertEqual(scores["categories"], {"xss": {"support": 2, "caught": 1, "recall": 0.5}})
        self.assertEqual(scores["ambiguity"]["ambiguous"]["confusion_matrix"], [[1, 0], [0, 1]])

    def test_pipeline_fits_categories_only_on_supplied_training_rows(self):
        train = np.array([[6, 10, -1], [6, 20, 2], [17, 40, -1], [17, 80, 0]])
        model = build_model("logistic", ("protocol", "duration_ms", "tcp_flags"))
        model.fit(train, [0, 0, 1, 1])
        encoder = model.named_steps["prepare"].named_transformers_["categorical"]
        self.assertEqual(encoder.categories_[0].tolist(), [6, 17])
        self.assertEqual(model.predict_proba([[58, 50, 7]]).shape, (1, 2))
