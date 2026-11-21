"""Synthetic tests for capture lineage and native exporter contracts."""

from datetime import datetime, timedelta, timezone
import unittest

from ml.level2_flow_schema import FlowValidationError
from ml.level2_provenance import (
    CIC_COUNTER_COLUMNS, CaptureBlock, check_capture_boundary, cic_native_counters, ton_v3_interval,
)


UTC = timezone.utc
DAY = datetime(2017, 7, 3, tzinfo=UTC)


def block(release="cicids2017-improved", capture_id="monday", start=DAY, attacks=20, digest=None):
    return CaptureBlock(
        release, capture_id, start, start + timedelta(hours=4), "Synthetic evidence", 100, attacks, digest,
    )


class CaptureBoundaryTests(unittest.TestCase):
    def test_aliases_share_parent_capture_across_cic_releases(self):
        with self.assertRaisesRegex(ValueError, "original capture ID"):
            check_capture_boundary([block()], [block(release="lycos-ids2017")])
        with self.assertRaisesRegex(ValueError, "capture lineage"):
            check_capture_boundary(
                [block()],
                [block(release="lycos-ids2017", capture_id="tuesday", start=DAY + timedelta(days=1))],
                require_distinct_lineages=True,
            )

    def test_original_capture_hash_detects_aliases_and_cannot_be_double_counted(self):
        train = block(digest="a" * 64)
        duplicate = block(release="ton-iot-zeek", capture_id="aliased", digest="A" * 64)
        with self.assertRaisesRegex(ValueError, "capture digest"):
            check_capture_boundary([train], [duplicate])
        with self.assertRaisesRegex(ValueError, "more than once"):
            check_capture_boundary([train, duplicate], [block(capture_id="tuesday")])

    def test_source_aware_time_comparison_and_chronological_order(self):
        first = block()
        with self.assertRaisesRegex(ValueError, "times overlap"):
            check_capture_boundary([first], [block(capture_id="alias", start=DAY + timedelta(hours=2))])
        boundary = block(capture_id="next", start=first.end)
        self.assertEqual(check_capture_boundary([first], [boundary], chronological=True).shared_lineages,
                         ("cic-ids2017",))
        with self.assertRaisesRegex(ValueError, "fit captures"):
            check_capture_boundary([boundary], [first], chronological=True)
        offset = timezone(timedelta(hours=-3))
        self.assertEqual(block(start=DAY.astimezone(offset)).start, DAY)

    def test_benign_only_capture_has_no_recall_support(self):
        train = block(capture_id="tuesday", start=DAY + timedelta(days=1))
        monday = block(attacks=0)
        with self.assertRaisesRegex(ValueError, "Attack recall"):
            check_capture_boundary([train], [monday])
        result = check_capture_boundary([train], [monday], require_attack_evaluation=False)
        self.assertEqual((result.evaluation_benign, result.evaluation_attacks), (100, 0))

    def test_declared_cross_lineage_boundary_retains_both_class_counts(self):
        details = check_capture_boundary(
            [block(release="nf-ton-iot-v3")], [block()], require_distinct_lineages=True,
        )
        self.assertEqual(details.shared_lineages, ())
        self.assertEqual(details.evaluation_attacks, 20)

    def test_blocks_need_timezones_and_a_supported_release(self):
        with self.assertRaisesRegex(ValueError, "timezone-aware"):
            block(start=DAY.replace(tzinfo=None))
        with self.assertRaisesRegex(ValueError, "outside"):
            block(release="nf-cse-cic-ids2018-v2")


class NativeAdapterTests(unittest.TestCase):
    def test_v3_interval_retains_millisecond_precision(self):
        start, end = ton_v3_interval({"FLOW_START_MILLISECONDS": "1234", "FLOW_END_MILLISECONDS": "1260"})
        self.assertEqual(start, datetime(1970, 1, 1, 0, 0, 1, 234000, tzinfo=UTC))
        self.assertEqual(end - start, timedelta(milliseconds=26))
        with self.assertRaisesRegex(ValueError, "precedes"):
            ton_v3_interval({"FLOW_START_MILLISECONDS": "2", "FLOW_END_MILLISECONDS": "1"})
        with self.assertRaises(FlowValidationError):
            ton_v3_interval({"FLOW_DURATION_MILLISECONDS": "20"})

    def test_cic_adapter_retains_payload_and_native_direction(self):
        record = dict(zip(CIC_COUNTER_COLUMNS, ("6", "1999", "2", "1", "0.0", "4"), strict=True))
        record.update({"Src Port": "443", "Label": "DDoS", "SYN Flag Count": "1"})
        counters = cic_native_counters(record)
        self.assertEqual(counters, (6, 1999, 2, 1, 0, 4))
        self.assertEqual(counters.forward_payload_octets, 0)
        self.assertNotIn("src_to_dst_octets", counters._fields)
        with self.assertRaises(FlowValidationError):
            cic_native_counters({**record, "Total Bwd packets": "-1"})
