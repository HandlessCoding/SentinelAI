"""Exercise the dataset inspector with small, temporary CSV files."""

from contextlib import redirect_stderr, redirect_stdout
import csv
import io
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from ml.inspect_dataset import inspect_training, main, validate_testing


HEADER = "id,proto,service,attack_cat,label\n"


class DatasetInspectionTests(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)

    def write_csv(self, name, contents):
        path = self.directory / name
        path.write_text(contents, encoding="utf-8")
        return path

    def test_training_summary(self):
        path = self.write_csv(
            "train.csv",
            HEADER + "1,tcp, ,Normal,0\n2,tcp, ,Normal,0\n3,udp,,Generic,1\n",
        )
        columns, rows, missing, duplicates, labels, types, categories, unusual = (
            inspect_training(path)
        )
        self.assertEqual(columns, ["id", "proto", "service", "attack_cat", "label"])
        self.assertEqual(rows, 3)
        self.assertEqual(missing, dict(id=0, proto=0, service=3, attack_cat=0, label=0))
        self.assertEqual(duplicates, 1)
        self.assertEqual(labels, {0: 2, 1: 1})
        self.assertEqual(types["id"], {"integer"})
        self.assertEqual(types["service"], set())
        self.assertEqual(types["proto"], {"text"})
        self.assertEqual(categories, {"Normal": 2, "Generic": 1})
        self.assertEqual(unusual, {})

    def test_training_reports_types_and_unusual_values(self):
        path = self.write_csv(
            "train.csv",
            "id,service,is_ftp_login,dur,attack_cat,label\n"
            "1,-,0,0,Normal,0\n2,ftp,4,0.25,Fuzzers,1\n",
        )
        *_, types, categories, unusual = inspect_training(path)
        self.assertEqual(types["dur"], {"integer", "decimal"})
        self.assertEqual(categories, {"Normal": 1, "Fuzzers": 1})
        self.assertEqual(unusual, {"service = '-'": 1, "is_ftp_login = '4'": 1})

    def test_training_rejects_invalid_label(self):
        path = self.write_csv("train.csv", HEADER + "1,tcp,http,Normal,2\n")
        with self.assertRaisesRegex(ValueError, "invalid binary label"):
            inspect_training(path)

    def test_test_partition_rejects_invalid_structure(self):
        columns = HEADER.strip().split(",")
        cases = {
            "row width": (HEADER + "1,tcp,http,0\n", "expected 5"),
            "column order": ("proto,id,service,attack_cat,label\n", "name and order"),
            "empty partition": (HEADER, "no data rows"),
            "malformed CSV": (HEADER + '1,"tcp,http,Normal,0\n', "unexpected end"),
        }
        for case, (contents, message) in cases.items():
            with self.subTest(case=case):
                path = self.write_csv("test.csv", contents)
                with self.assertRaisesRegex((ValueError, csv.Error), message):
                    validate_testing(path, columns)

    def test_cli_reports_training_and_only_validates_test_structure(self):
        train = self.write_csv("train.csv", HEADER + "1,tcp,http,Normal,0\n")
        # The test value is deliberately invalid as a label but valid as a CSV field.
        test = self.write_csv("test.csv", HEADER + "1,tcp,http,Normal,test-only\n")
        output = io.StringIO()
        with redirect_stdout(output):
            result = main(["--train", str(train), "--test", str(test)])
        self.assertEqual(result, 0)
        self.assertIn("0 (normal): 1 (100.00%)", output.getvalue())
        self.assertIn("1 (attack): 0 (0.00%)", output.getvalue())
        self.assertTrue(output.getvalue().endswith("Test CSV structure: valid (1 records)\n"))
        self.assertNotIn("test-only", output.getvalue())

    def test_cli_reports_missing_training_file(self):
        path = self.directory / "missing.csv"
        errors = io.StringIO()
        with redirect_stderr(errors):
            result = main(["--train", str(path)])
        self.assertEqual(result, 1)
        self.assertIn(f"Training CSV ({path})", errors.getvalue())
