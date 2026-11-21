import unittest

from ml.level2_splits import (
    ClassSupport,
    VectorGroup,
    fold_for_vector,
    plan_capture_folds,
    plan_capture_holdout,
    plan_vector_folds,
)


PROVENANCE = "synthetic source manifest"


class VectorSplitTests(unittest.TestCase):
    def test_seeded_assignment_is_stable_and_uses_canonical_bytes(self):
        keys = [bytes([number]) for number in range(1, 7)]
        expected = [0, 2, 1, 0, 1, 0]
        self.assertEqual([fold_for_vector(key) for key in keys], expected)
        self.assertEqual(fold_for_vector(bytes(bytearray(keys[4]))), expected[4])
        self.assertNotEqual([fold_for_vector(key, seed=43) for key in keys], expected)

    def test_group_multiplicities_and_conflicts_stay_together(self):
        groups = (
            VectorGroup(b"\x01", 4, 1),
            VectorGroup(b"\x02", 2, 3),
            VectorGroup(b"\x03", 3, 2),
            VectorGroup(b"\x04", 2, 0),
        )
        plan = plan_vector_folds(iter(groups))
        self.assertEqual(plan.folds[0].validation, ClassSupport(6, 1, 2))
        self.assertEqual(plan.folds[0].training, ClassSupport(5, 5, 2))
        self.assertEqual(plan.largest_vector_rows, 5)
        self.assertEqual(plan.exact_vector_overlap, 0)
        self.assertIsNone(plan.capture_overlap)
        self.assertIsNone(plan.session_overlap)
        self.assertTrue(all(fold.has_class_support for fold in plan.folds))

    def test_reports_empty_or_single_class_partitions(self):
        groups = [VectorGroup(b"\x01", 1_000_000, 1), VectorGroup(b"\x02", 0, 2)]
        plan = plan_vector_folds(groups)
        self.assertEqual(plan.largest_component_rows, 1_000_001)
        self.assertEqual(plan.folds[1].validation.rows, 0)
        self.assertTrue(all(not fold.has_class_support for fold in plan.folds))

    def test_checks_support_on_training_and_validation_with_configured_minimum(self):
        groups = [VectorGroup(bytes([number]), 2, 2) for number in range(1, 4)]
        plan = plan_vector_folds(groups, minimum_class_rows=3)
        self.assertFalse(any(fold.has_class_support for fold in plan.folds))
        self.assertTrue(all(fold.training == ClassSupport(4, 4, 2) for fold in plan.folds))

    def test_rejects_repeated_unsorted_or_invalid_group_summaries(self):
        first = VectorGroup(b"a", 1, 1)
        other = VectorGroup(b"b", 1, 0)
        for groups in ((first, first), (other, first), (VectorGroup(b"a", -1, 2),)):
            with self.subTest(groups=groups), self.assertRaises(ValueError):
                plan_vector_folds(groups)
        with self.assertRaises(ValueError):
            plan_vector_folds(())
        with self.assertRaises(ValueError):
            fold_for_vector(b"a", fold_count=1)


class ProvenanceSplitTests(unittest.TestCase):
    def test_capture_and_session_components_include_transitive_edges(self):
        groups = (
            VectorGroup(b"a", 4, 3, ("capture-a",), ("session-shared",)),
            VectorGroup(b"b", 0, 5, ("capture-b",), ("session-shared",)),
            VectorGroup(b"c", 2, 1, ("capture-c", "capture-b"), ("session-c",)),
            VectorGroup(b"d", 3, 4, ("capture-d",), ("session-d",)),
        )
        plan = plan_capture_folds(iter(groups), fold_count=2, provenance_reference=PROVENANCE)
        main = plan.capture_folds["capture-a"]
        self.assertEqual(plan.capture_folds["capture-b"], main)
        self.assertEqual(plan.capture_folds["capture-c"], main)
        self.assertEqual(plan.session_folds["session-c"], main)
        self.assertNotEqual(plan.capture_folds["capture-d"], main)
        self.assertEqual(plan.folds[main].validation, ClassSupport(6, 9, 3))
        self.assertEqual(plan.folds[main].training, ClassSupport(3, 4, 1))
        self.assertEqual(plan.largest_vector_rows, 7)
        self.assertEqual(plan.largest_component_rows, 15)
        self.assertEqual((plan.exact_vector_overlap, plan.capture_overlap, plan.session_overlap), (0, 0, 0))

    def test_missing_session_metadata_is_unobservable_even_with_capture_ids(self):
        groups = (
            VectorGroup(b"a", 2, 1, ("capture-a",), ("session-a",)),
            VectorGroup(b"b", 3, 4, ("capture-b",)),
        )
        plan = plan_capture_folds(groups, fold_count=2, provenance_reference=PROVENANCE)
        self.assertEqual(plan.capture_overlap, 0)
        self.assertIsNone(plan.session_overlap)
        self.assertEqual(plan.session_folds["session-a"], plan.capture_folds["capture-a"])

    def test_provenance_required_for_every_group(self):
        with self.assertRaisesRegex(ValueError, "cover every vector group"):
            plan_capture_folds([VectorGroup(b"a", 1, 1)], provenance_reference=PROVENANCE)
        with self.assertRaisesRegex(ValueError, "verified capture provenance"):
            plan_capture_folds([VectorGroup(b"a", 1, 1, ("capture-a",))], provenance_reference="")

    def test_holds_out_whole_development_capture(self):
        groups = (
            VectorGroup(b"a", 3, 4, ("capture-a",), ("session-a",)),
            VectorGroup(b"b", 1, 2, ("capture-b", "capture-c"), ("session-b",)),
        )
        plan = plan_capture_holdout(
            groups, validation_captures=("capture-b", "capture-c"), provenance_reference=PROVENANCE
        )
        self.assertEqual(plan.capture_folds, {"capture-a": 0, "capture-b": 1, "capture-c": 1})
        self.assertEqual(len(plan.folds), 1)
        self.assertEqual(plan.folds[0].validation_fold, 1)
        self.assertEqual(plan.folds[0].validation, ClassSupport(1, 2, 1))
        self.assertEqual(plan.folds[0].training, ClassSupport(3, 4, 1))
        self.assertTrue(plan.folds[0].has_class_support)

    def test_refuses_capture_boundaries_crossed_by_vector_or_session(self):
        shared_vector = [VectorGroup(b"a", 3, 4, ("capture-a", "capture-b"))]
        shared_session = [
            VectorGroup(b"a", 2, 3, ("capture-a",), ("session-a",)),
            VectorGroup(b"b", 3, 1, ("capture-b",), ("session-a",)),
        ]
        for groups in (shared_vector, shared_session):
            with self.subTest(groups=groups), self.assertRaisesRegex(ValueError, "holdout boundary shares"):
                plan_capture_holdout(groups, validation_captures=["capture-b"], provenance_reference=PROVENANCE)

    def test_component_overflow_leaves_fold_support_unmet(self):
        groups = [VectorGroup(b"a", 1, 1, ("capture-a", "capture-b"))]
        plan = plan_capture_folds(groups, fold_count=2, provenance_reference=PROVENANCE)
        self.assertEqual(plan.largest_component_rows, 2)
        self.assertFalse(any(fold.has_class_support for fold in plan.folds))


if __name__ == "__main__":
    unittest.main()
