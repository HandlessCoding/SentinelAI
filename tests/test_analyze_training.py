"""Check that duplicate and conflict totals count the right training rows."""

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from ml.analyze_training import analyze_training


HEADER = "id,proto,service,is_ftp_login,ct_ftp_cmd,attack_cat,label\n"


class TrainingAnalysisTests(unittest.TestCase):
    def analyze(self, *rows):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "train.csv"
            path.write_text(HEADER + "".join(rows), encoding="utf-8")
            return analyze_training(path)

    def test_duplicates_conflicts_and_category_counts(self):
        report = self.analyze(
            "1,tcp,-,0,0,Normal,0\n",
            "2,tcp,-,0,0,Normal,0\n",
            "3,tcp,-,0,0,Fuzzers,1\n",
            "4,tcp,-,0,0,Shellcode,1\n",
            "5,tcp,ftp,2,2,Fuzzers,1\n",
            "6,tcp,ftp,2,2,Generic,1\n",
            "7,udp,dns,0,0,Normal,0\n",
        )
        self.assertEqual(report["original"], {"0": 3, "1": 4})
        self.assertEqual(report["exact_dedup"], {"0": 2, "1": 4})
        self.assertEqual(report["unique_vectors"], 3)
        self.assertEqual(report["conflicting_vectors"], 1)
        self.assertEqual(report["conflict_categories"], {"Normal": 2, "Fuzzers": 1, "Shellcode": 1})
        self.assertEqual(report["categories"]["Fuzzers"], 2)
        self.assertEqual(report["unambiguous_dedup"], {"0": 1, "1": 1})
        self.assertEqual(report["unusual_ftp"], {("2", "ftp", "2"): 2})
        self.assertEqual(report["ftp_values"], {"0": 5, "2": 2})
        self.assertEqual(report["service_dash_by_label"], {"0": 2, "1": 2})
        self.assertEqual(report["service_dash_by_proto"], {"tcp": 4})

    def test_all_vectors_conflict(self):
        report = self.analyze("1,tcp,-,0,0,Normal,0\n", "2,tcp,-,0,0,Fuzzers,1\n")
        self.assertEqual(report["conflicting_vectors"], 1)
        self.assertFalse(report["unambiguous_dedup"])

    def test_rejects_empty_data(self):
        with self.assertRaisesRegex(ValueError, "no data rows"):
            self.analyze()

    def test_rejects_invalid_label(self):
        with self.assertRaisesRegex(ValueError, "invalid binary label"):
            self.analyze("1,tcp,-,0,0,Normal,2\n")
