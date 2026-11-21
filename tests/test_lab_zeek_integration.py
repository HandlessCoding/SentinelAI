"""Exercise the real offline Zeek command when a supported binary is available."""

import os
from pathlib import Path
from shutil import which
from tempfile import TemporaryDirectory
import unittest

from ml.lab_capture import capture_rows
from ml.lab_demo import START, demo
from ml.lab_registry import NANOSECOND, digest, load_verified, read_object


class RealZeekIntegrationTests(unittest.TestCase):
    def test_synthetic_pcap_to_registered_flows(self):
        binary = os.environ.get("SENTINELAI_ZEEK_BINARY") or which("zeek")
        if not binary:
            self.skipTest("real Zeek is unavailable (set SENTINELAI_ZEEK_BINARY)")
        with TemporaryDirectory() as directory:
            root = Path(directory) / "real-zeek"
            result = demo(root, binary)
            manifest, windows = load_verified(root, "fixture")
            receipt = read_object(root / "zeek/fixture/run.json")
            self.assertEqual(receipt["pcap_sha256"], digest(root / "fixture.pcap", pcap=True))
            self.assertEqual(receipt["conn_sha256"], manifest["sha256"]["conn_log"])
            self.assertIn("zeek", receipt["zeek_version"].casefold())

            rows = sorted(capture_rows(root, manifest, windows), key=lambda entry: entry[0].timestamp_ns)
            self.assertEqual([row[0].timestamp_ns for row in rows],
                             [(START + offset) * NANOSECOND for offset in (1, 4, 7)])
            self.assertEqual([label[0] for _, label in rows], ["benign", "attack", "unknown"])
            for flow, _ in rows:
                self.assertTrue(flow.core_eligible)
                expected = {"proto": "udp", "orig_pkts": 1, "resp_pkts": 1, "orig_ip_bytes": 32,
                            "resp_ip_bytes": 32, "orig_bytes": 4, "resp_bytes": 4, "duration_ns": 125_000_000}
                self.assertEqual({field: flow.features[field] for field in expected}, expected)
            self.assertEqual(result["roles"]["fit"]["eligible"], {})

    def test_registered_g26_benign_capture(self):
        lab = os.environ.get("SENTINELAI_G26_LAB_ROOT")
        if not lab:
            self.skipTest("set SENTINELAI_G26_LAB_ROOT to the local G26 capture registry")
        root = Path(lab)
        capture_id = "g26-benign-01-reviewed"
        manifest, windows = load_verified(root, capture_id)
        original, original_windows = load_verified(root, "g26-benign-01")
        self.assertEqual(manifest["capture"]["session_id"], original["capture"]["session_id"])
        self.assertEqual(manifest["sha256"]["pcap"], original["sha256"]["pcap"])
        self.assertEqual(manifest["sha256"]["conn_log"], original["sha256"]["conn_log"])
        self.assertTrue(all(label == "unknown" for _, (label, _, _) in capture_rows(root, original, original_windows)))
        self.assertEqual(manifest["capture"]["source"], "authorized_lab")
        self.assertEqual(manifest["capture"]["scenario"], "ordinary-http-smoke")
        rows = list(capture_rows(root, manifest, windows))
        self.assertTrue(all(label != "attack" for _, (label, _, _) in rows))
        benign = [flow for flow, (label, _, _) in rows if label == "benign"]
        self.assertEqual(len(benign), 1)
        self.assertTrue(benign[0].core_eligible)
        self.assertEqual(benign[0].features["proto"], "tcp")
        self.assertGreater(benign[0].features["orig_pkts"], 0)
        self.assertGreater(benign[0].features["resp_pkts"], 0)
        self.assertEqual(benign[0].features["duration_ns"], 28_464_079)
