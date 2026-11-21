"""Tests for exact, bounded group aggregation using synthetic keys."""

from collections import Counter
from contextlib import ExitStack
from dataclasses import asdict
from pathlib import Path
from random import Random
from tempfile import TemporaryDirectory
import unittest

from ml.level2_audit_storage import ExactGroupCounter, GroupSummary


class ExactGroupCounterTests(unittest.TestCase):
    def setUp(self):
        stack = ExitStack()
        self.addCleanup(stack.close)
        self.scratch = Path(stack.enter_context(TemporaryDirectory()))

    def test_empty_and_in_memory_groups(self):
        with ExactGroupCounter(self.scratch) as counter:
            self.assertFalse(any(asdict(counter.finish()).values()))
        with ExactGroupCounter(self.scratch) as counter:
            counter.add(b"record")
            counter.add(b"record")
            counter.add(b"else")
            result = counter.finish()
        self.assertEqual(result.rows, 3)
        self.assertEqual(result.distinct_groups, 2)
        self.assertEqual(result.duplicate_occurrences, 1)
        self.assertEqual(result.duplicate_groups, 1)
        self.assertEqual(result.duplicate_rows, 2)
        self.assertEqual(result.conflicting_rows, 0)

    def test_exact_groups_and_conflicts_across_compacted_runs(self):
        rows = [
            (b"a", 0),
            (b"", None),
            (b"a\x00", 1),
            (b"a", 1),
            (b"b", 1),
            (b"a\x00", 0),
            (b"a", None),
            (b"b", 1),
            (b"aa", 0),
        ]
        with ExactGroupCounter(
            self.scratch, max_chunk_bytes=300, merge_fan_in=2,
        ) as counter:
            for key, label in rows:
                counter.add(key, label)
            self.assertTrue(any(self.scratch.rglob("*.run")))
            result = counter.finish()
            self.assertIs(result, counter.finish())
            self.assertFalse(any(self.scratch.rglob("*.run")))
        self.assertEqual(result, GroupSummary(
            rows=9,
            distinct_groups=5,
            duplicate_occurrences=4,
            duplicate_groups=3,
            duplicate_rows=7,
            conflicting_groups=2,
            conflicting_rows=5,
            conflicting_normal_rows=2,
            conflicting_attack_rows=2,
            max_group_size=3,
        ))
        self.assertEqual(list(self.scratch.iterdir()), [])

    def test_deterministic_for_many_runs_and_different_orders(self):
        rng = Random(13)
        rows = [
            (rng.randrange(80).to_bytes(2, "big"), rng.choice((None, 0, 1)))
            for _ in range(500)
        ]
        totals = Counter(key for key, _ in rows)
        normals = Counter(key for key, label in rows if label == 0)
        attacks = Counter(key for key, label in rows if label == 1)
        conflicts = normals.keys() & attacks.keys()
        repeats = {key: count for key, count in totals.items() if count > 1}
        expected = GroupSummary(
            rows=len(rows),
            distinct_groups=len(totals),
            duplicate_occurrences=len(rows) - len(totals),
            duplicate_groups=len(repeats),
            duplicate_rows=sum(repeats.values()),
            conflicting_groups=len(conflicts),
            conflicting_rows=sum(totals[key] for key in conflicts),
            conflicting_normal_rows=sum(normals[key] for key in conflicts),
            conflicting_attack_rows=sum(attacks[key] for key in conflicts),
            max_group_size=max(totals.values()),
        )
        for budget, fan_in, records in (
            (1000, 3, rows),
            (1200, 2, reversed(rows)),
            (100000, 2, rows),
        ):
            with self.subTest(budget=budget, fan_in=fan_in):
                with ExactGroupCounter(
                    self.scratch, max_chunk_bytes=budget, merge_fan_in=fan_in,
                ) as counter:
                    for key, label in records:
                        counter.add(key, label)
                    self.assertEqual(counter.finish(), expected)

    def test_scratch_files_are_cleaned_if_processing_aborts(self):
        with self.assertRaisesRegex(RuntimeError, "stop"):
            with ExactGroupCounter(self.scratch, max_chunk_bytes=300) as counter:
                counter.add(b"first")
                counter.add(b"second")
                self.assertTrue(any(self.scratch.rglob("*.run")))
                raise RuntimeError("stop")
        self.assertEqual(list(self.scratch.iterdir()), [])

    def test_rejects_invalid_records_and_disallows_new_rows_after_finish(self):
        counter = ExactGroupCounter(self.scratch, max_chunk_bytes=300)
        with self.assertRaisesRegex(RuntimeError, "with block"):
            counter.add(b"outside")
        with counter:
            with self.assertRaisesRegex(TypeError, "must be bytes"):
                counter.add("text")
            with self.assertRaisesRegex(ValueError, "label"):
                counter.add(b"bad-label", 2)
            with self.assertRaisesRegex(ValueError, "chunk budget"):
                counter.add(b"x" * 301)
            self.assertEqual(counter.finish().rows, 0)
            with self.assertRaisesRegex(RuntimeError, "already finalized"):
                counter.add(b"extra")
        with self.assertRaisesRegex(RuntimeError, "single-use"):
            with counter:
                self.fail("an exited counter was reopened")
