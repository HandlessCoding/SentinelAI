"""Verify deterministic candidate feature selection with synthetic flow records."""

from struct import Struct
import unittest

from ml.level2_feature_sets import FEATURE_SETS, FeatureSelector
from ml.level2_flow_schema import FlowValidationError, normalize_flow


def flow(**updates):
    record = {
        "PROTOCOL": "6",
        "FLOW_DURATION_MILLISECONDS": "50",
        "IN_PKTS": "2",
        "OUT_PKTS": "1",
        "IN_BYTES": "140",
        "OUT_BYTES": "40",
        "L4_SRC_PORT": "50000",
        "L4_DST_PORT": "443",
        "TCP_FLAGS": "18",
        "CLIENT_TCP_FLAGS": "2",
        "SERVER_TCP_FLAGS": "18",
        "MIN_IP_PKT_LEN": "40",
        "MAX_IP_PKT_LEN": "100",
        "MIN_TTL": "60",
        "MAX_TTL": "63",
        "RETRANSMITTED_IN_PKTS": "2",
        "RETRANSMITTED_OUT_PKTS": "3",
        "RETRANSMITTED_IN_BYTES": "4",
        "RETRANSMITTED_OUT_BYTES": "5",
    }
    record.update(updates)
    return record


class FeatureSetTests(unittest.TestCase):
    def test_core_values_and_binary_keys_match_g14(self):
        record = flow(IN_BYTES="00140.0")
        expected = normalize_flow(record).as_tuple()
        self.assertEqual(FEATURE_SETS["core"].select(record), expected)
        self.assertEqual(FEATURE_SETS["core"].pack(expected), Struct(">B5Q").pack(*expected))

    def test_candidate_keys_ignore_labels_and_environment_identifiers(self):
        selector = FeatureSelector()
        changed = {
            "Label": "1",
            "Attack": "Sample class",
            "IPV4_SRC_ADDR": "192.0.2.1",
            "IPV4_DST_ADDR": "198.51.100.1",
            "session_id": "one",
            "Dataset": "fixture",
            "L7_PROTO": "12",
            "DNS_QUERY_ID": "45",
        }
        vectors = selector.prepare(flow())
        self.assertEqual(vectors, selector.prepare(flow(**changed)))
        self.assertTrue(set(changed).isdisjoint(selector.source_columns))
        for name, vector in vectors.items():
            spec = FEATURE_SETS[name]
            self.assertEqual(len(spec.pack(vector)), spec.key_bytes)

    def test_directional_values_are_separate_and_ordered(self):
        vectors = FeatureSelector().prepare(flow())
        self.assertEqual(vectors["core_ports"][-2:], (50000, 443))
        self.assertEqual(vectors["core_tcp_flags"][-3:], (18, 2, 18))
        self.assertEqual(vectors["core_packet_lengths"][-2:], (40, 100))
        self.assertEqual(vectors["core_ttl"][-2:], (60, 63))
        self.assertEqual(vectors["core_retransmissions"][-4:], (2, 3, 4, 5))

    def test_fields_without_protocol_meaning_are_structural_nulls(self):
        selector = FeatureSelector()
        udp = selector.prepare(flow(PROTOCOL="17", TCP_FLAGS="not-applicable"))
        self.assertEqual(udp["core_ports"][-2:], (50000, 443))
        self.assertEqual(udp["core_tcp_flags"][-3:], (None, None, None))
        self.assertEqual(udp["core_retransmissions"][-4:], (None, None, None, None))
        icmp = selector.prepare(flow(PROTOCOL="1", L4_SRC_PORT="not-applicable"))
        ports = FEATURE_SETS["core_ports"]
        vector = icmp["core_ports"]
        self.assertEqual(vector[-2:], (None, None))
        self.assertNotEqual(ports.pack(vector), ports.pack((*vector[:-2], 0, 0)))

    def test_missing_applicable_field_only_rejects_containing_candidates(self):
        vectors = FeatureSelector().prepare(flow(MAX_IP_PKT_LEN=" "))
        self.assertIsInstance(vectors["core"], tuple)
        self.assertIsInstance(vectors["core_ttl"], tuple)
        for name in ("core_packet_lengths", "core_lengths_flags", "core_all"):
            error = vectors[name]
            self.assertEqual((error.column, error.reason), ("MAX_IP_PKT_LEN", "missing"))

    def test_rejects_out_of_range_ports_protocol_and_reversed_ranges(self):
        vectors = FeatureSelector().prepare(flow(L4_DST_PORT="65536", MAX_TTL="12", MAX_IP_PKT_LEN="3"))
        self.assertEqual(vectors["core_ports"].reason, "out_of_range")
        self.assertEqual(vectors["core_ttl"].reason, "below_reported_minimum")
        self.assertEqual(vectors["core_packet_lengths"].reason, "below_reported_minimum")
        for result in FeatureSelector().prepare(flow(PROTOCOL="256")).values():
            self.assertEqual((result.column, result.reason), ("PROTOCOL", "out_of_range"))

    def test_bind_handles_reordered_and_extra_columns(self):
        record = flow(Label="1")
        header = tuple(reversed(record))
        selector = FeatureSelector(("core_all", "core"))
        bound = selector.bind(header)
        self.assertEqual(bound.prepare([record[name] for name in header]), selector.prepare(record))
        with self.assertRaisesRegex(ValueError, "unique"):
            selector.bind((*header, "Label"))
        with self.assertRaisesRegex(ValueError, "lacks required feature columns"):
            selector.bind(("Label",))
        with self.assertRaisesRegex(FlowValidationError, "invalid_width"):
            bound.prepare(["1"])
