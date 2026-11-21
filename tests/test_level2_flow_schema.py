"""Synthetic contract tests for the Level 2 UQ NetFlow adapter."""

import unittest

from ml.level2_flow_schema import (
    CANONICAL_COLUMNS,
    MAX_FLOW_VALUE,
    SOURCE_COLUMNS,
    FlowValidationError,
    normalize_flow,
)


def flow(**overrides):
    return dict(zip(SOURCE_COLUMNS, ("6", "01.000", " 3 ", "4", "120", "240"))) | overrides


class Level2FlowSchemaTests(unittest.TestCase):
    def assert_rejected(self, record, column, reason):
        with self.assertRaises(FlowValidationError) as error:
            normalize_flow(record)
        self.assertEqual((error.exception.column, error.exception.reason), (column, reason))

    def test_preparation_preserves_direction_and_selects_six_fields(self):
        features = normalize_flow(flow(
            IPV4_SRC_ADDR="192.0.2.1",
            IPV4_DST_ADDR="198.51.100.2",
            L4_DST_PORT=443,
            Label=1,
            Attack="Synthetic test category",
            Dataset="test fixture",
            FLOW_START_MILLISECONDS=12345,
        ))
        self.assertEqual(features.as_tuple(), (6, 1, 3, 4, 120, 240))
        self.assertEqual(features.as_dict(), {
            "protocol": 6,
            "duration_ms": 1,
            "src_to_dst_packets": 3,
            "dst_to_src_packets": 4,
            "src_to_dst_octets": 120,
            "dst_to_src_octets": 240,
        })
        self.assertEqual(tuple(features.as_dict()), CANONICAL_COLUMNS)

    def test_equivalent_integer_spellings_share_an_exact_key(self):
        reference = normalize_flow(flow(FLOW_DURATION_MILLISECONDS=1)).as_tuple()
        alternative = normalize_flow(flow(FLOW_DURATION_MILLISECONDS="00001.0")).as_tuple()
        self.assertEqual({reference, alternative}, {reference})

    def test_zero_is_preserved_and_uint64_is_exact(self):
        features = normalize_flow(flow(
            PROTOCOL=0, FLOW_DURATION_MILLISECONDS="0", OUT_PKTS="0.0",
            OUT_BYTES=0, IN_BYTES=str(MAX_FLOW_VALUE),
        ))
        self.assertEqual(features.as_tuple(), (0, 0, 3, 0, MAX_FLOW_VALUE, 0))

    def test_missing_values_include_absent_none_and_blank_fields(self):
        record = flow()
        del record["IN_PKTS"]
        self.assert_rejected(record, "IN_PKTS", "missing")
        for value in (None, "", " \t"):
            with self.subTest(value=value):
                self.assert_rejected(flow(IN_PKTS=value), "IN_PKTS", "missing")

    def test_invalid_integer_values_are_rejected_without_rounding(self):
        for value in (True, 1.0, "1.5", "1e3", "NaN", "Infinity", "1_000", "１２"):
            with self.subTest(value=value):
                self.assert_rejected(flow(IN_BYTES=value), "IN_BYTES", "invalid_integer")

    def test_unsigned_integer_ranges_are_enforced(self):
        for value in (256, -1, "256"):
            with self.subTest(value=value):
                self.assert_rejected(flow(PROTOCOL=value), "PROTOCOL", "out_of_range")
        for value in (MAX_FLOW_VALUE + 1, str(MAX_FLOW_VALUE + 1), "9" * 5000):
            with self.subTest(value_type=type(value)):
                self.assert_rejected(flow(OUT_BYTES=value), "OUT_BYTES", "out_of_range")

    def test_non_mapping_and_rejected_value_do_not_appear_in_errors(self):
        self.assert_rejected(["6", "1", "3", "4", "120", "240"], "record", "invalid_mapping")
        with self.assertRaises(FlowValidationError) as error:
            normalize_flow(flow(PROTOCOL="synthetic rejected value"))
        self.assertEqual(str(error.exception), "PROTOCOL: invalid_integer")
