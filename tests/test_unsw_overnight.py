"""Exercise the data boundary, grouping, and unattended checkpoint controls."""

from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event
import unittest
from unittest.mock import patch

import numpy as np

from ml.inference import FEATURE_TYPES
from ml.run_baseline import TrainingData
from ml.run_unsw_overnight import Halt, checkpoint, is_active, read_json, run, run_lock, status, watchdog
from ml.unsw_development_split import normalize_predictors
from ml.unsw_overnight_data import FEATURE_SETS, plan_folds, project_csv, read_g32_fit_indices
from ml.unsw_overnight_models import aggregate_folds, configurations, rank_candidates


def grouped_fixture():
    columns = list(FEATURE_TYPES)
    rows = []
    for index in range(200):
        fields = dict.fromkeys(columns, "0")
        fields.update(dur=str(index // 2), proto="tcp", service="-", state="FIN",
                      sttl=str(32 + (index % 2)), ct_srv_src=str(index % 2))
        rows.append([fields[name] for name in columns])
    return normalize_predictors(TrainingData(columns, np.array(rows, dtype=object), np.arange(200) % 2, np.arange(200)))


def fold_result(fold, recall=0.96, fpr=0.04):
    metrics = {"accuracy": 0.95, "precision": 0.95, "recall": recall,
               "false_positive_rate": fpr, "balanced_accuracy": 0.95}
    return {"fold": fold, "calibrated": metrics, "default": metrics, "fit_seconds": 1.0, "cpu_seconds": 0.5}


class OvernightTests(unittest.TestCase):
    def test_projection_uses_selected_lines_and_rejects_changed_source(self):
        with TemporaryDirectory() as location:
            root = Path(location)
            source, target = root / "source.csv", root / "fit-only.csv"
            source.write_bytes(b"value,label\n1,0\n\xff-withheld\n3,1\n")
            digest = sha256(source.read_bytes()).hexdigest()
            selected = np.array([0, 2])
            kwargs = {"expected_digest": digest, "expected_rows": 3}
            first = project_csv(source, selected, target, **kwargs)
            self.assertEqual(target.read_text(), "value,label\n1,0\n3,1\n")
            self.assertEqual(project_csv(source, selected, target, **kwargs), first)
            source.write_bytes(b"value,label\n1,0\nchanged\n3,1\n")
            with self.assertRaisesRegex(ValueError, "checksum"):
                project_csv(source, selected, target, **kwargs)
            self.assertEqual(target.read_text(), "value,label\n1,0\n3,1\n")

    def test_archive_reads_only_fit_member(self):
        with TemporaryDirectory() as location:
            path = Path(location) / "partitions.npz"
            np.savez_compressed(path, fit=np.array([1, 4]), calibration=np.array([object()], dtype=object),
                                comparison=np.array([object()], dtype=object), final_validation=np.array([object()], dtype=object))
            with patch("ml.unsw_overnight_data.G32_ARCHIVE_SHA256", sha256(path.read_bytes()).hexdigest()), patch(
                "ml.unsw_overnight_data.G32_ARCHIVE_BYTES", path.stat().st_size
            ), patch("ml.unsw_overnight_data.FIT_ROWS", 2), patch("ml.unsw_overnight_data.SOURCE_ROWS", 6):
                np.testing.assert_array_equal(read_g32_fit_indices(path), [1, 4])

    def test_ablation_groups_are_isolated_in_every_role_and_rotation(self):
        data = grouped_fixture()
        folds, audit = plan_folds(data, minimum_class_rows=5)
        self.assertFalse(audit["blockers"])
        self.assertEqual(audit["groups"]["full"]["groups"], 200)
        self.assertEqual(audit["groups"]["no_context"]["groups"], 100)
        for fold in folds:
            group_role = next(indices for indices in fold.values() if 0 in indices)
            self.assertIn(1, group_role)
        self.assertEqual({name for name in FEATURE_SETS["full"] if name not in FEATURE_SETS["no_ttl"]},
                         {"sttl", "dttl", "ct_state_ttl"})

    def test_ranking_prioritizes_recall_stability_across_folds(self):
        volatile = aggregate_folds([fold_result(1, recall=0.99, fpr=0.01), fold_result(2, recall=0.94, fpr=0.01)])
        stable = aggregate_folds([fold_result(1, recall=0.96, fpr=0.05), fold_result(2, recall=0.95, fpr=0.05)])
        candidates = [{"config": {"id": name}, "aggregate": aggregate}
                      for name, aggregate in (("volatile", volatile), ("stable", stable))]
        self.assertEqual(rank_candidates(candidates)[0]["config"]["id"], "stable")

    def test_resume_skips_saved_folds_and_completed_configurations(self):
        config = next(item for item in configurations() if item["id"] == "rf-reference-no_ttl")
        data = grouped_fixture()
        folds, audit = plan_folds(data, minimum_class_rows=5)
        first = [fold_result(1), Halt("safe stop requested")]
        with TemporaryDirectory() as location:
            directory = Path(location)
            with patch("ml.run_unsw_overnight.configurations", return_value=[config]), patch(
                "ml.run_unsw_overnight.load_overnight_data", return_value=(data, {"fixture": True})
            ), patch("ml.run_unsw_overnight.plan_folds", return_value=(folds, audit)), patch(
                "ml.run_unsw_overnight.peak_rss_bytes", return_value=1024
            ):
                with patch("ml.run_unsw_overnight.fit_fold", side_effect=first):
                    self.assertEqual(run(directory, True), 2)
                    manifest = read_json(directory / "plan.json")
                    self.assertEqual(status(directory, manifest)["finished_folds"], 1)
                with patch("ml.run_unsw_overnight.fit_fold", side_effect=[fold_result(i) for i in range(2, 6)]) as fit:
                    self.assertEqual(run(directory, True), 0)
                    self.assertEqual([call.args[-2] for call in fit.call_args_list], [2, 3, 4, 5])
                    self.assertEqual(run(directory, True), 0)
                    self.assertEqual(fit.call_count, 4)
                self.assertEqual(checkpoint(directory, config)[1]["status"], "completed")
                self.assertEqual(read_json(directory / "plan.json")["deadline_epoch"], manifest["deadline_epoch"])

    def test_lock_and_watchdog_keep_interruption_observable(self):
        with TemporaryDirectory() as location:
            directory = Path(location)
            with run_lock(directory):
                self.assertTrue(is_active(directory))
            self.assertFalse(is_active(directory))
            with patch("ml.run_unsw_overnight.limit_reason", return_value="wall-clock deadline reached"), patch(
                "ml.run_unsw_overnight.peak_rss_bytes", return_value=1234
            ), patch("ml.run_unsw_overnight.os._exit", side_effect=SystemExit) as exit_process:
                with self.assertRaises(SystemExit):
                    watchdog(directory, 0.0, "fixture", Event())
                exit_process.assert_called_once_with(2)
            self.assertEqual(read_json(directory / "interrupt-fixture.json")["reason"], "wall-clock deadline reached")
