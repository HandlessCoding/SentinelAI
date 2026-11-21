"""Audit the local NF-ToN-IoT-v2 development CSV without fitting a model."""

import argparse
from collections import Counter
import csv
from dataclasses import asdict
from functools import lru_cache
from hashlib import file_digest
from io import TextIOWrapper
from ipaddress import IPv4Address
from itertools import islice
import json
from math import isfinite
from operator import itemgetter
from os import fstat
from pathlib import Path
from struct import Struct
import sys

from ml.level2_audit_storage import ExactGroupCounter
from ml.level2_flow_schema import FlowValidationError, SCHEMA_VERSION, SOURCE_COLUMNS, normalize_flow


PUBLISHED_FEATURES = (
    "IPV4_SRC_ADDR", "IPV4_DST_ADDR", "L4_SRC_PORT", "L4_DST_PORT", "PROTOCOL", "L7_PROTO",
    "IN_BYTES", "OUT_BYTES", "IN_PKTS", "OUT_PKTS", "FLOW_DURATION_MILLISECONDS",
    "TCP_FLAGS", "CLIENT_TCP_FLAGS", "SERVER_TCP_FLAGS", "DURATION_IN", "DURATION_OUT",
    "MIN_TTL", "MAX_TTL", "LONGEST_FLOW_PKT", "SHORTEST_FLOW_PKT", "MIN_IP_PKT_LEN",
    "MAX_IP_PKT_LEN", "SRC_TO_DST_SECOND_BYTES", "DST_TO_SRC_SECOND_BYTES",
    "RETRANSMITTED_IN_BYTES", "RETRANSMITTED_IN_PKTS", "RETRANSMITTED_OUT_BYTES",
    "RETRANSMITTED_OUT_PKTS", "SRC_TO_DST_AVG_THROUGHPUT", "DST_TO_SRC_AVG_THROUGHPUT",
    "NUM_PKTS_UP_TO_128_BYTES", "NUM_PKTS_128_TO_256_BYTES", "NUM_PKTS_256_TO_512_BYTES",
    "NUM_PKTS_512_TO_1024_BYTES", "NUM_PKTS_1024_TO_1514_BYTES", "TCP_WIN_MAX_IN",
    "TCP_WIN_MAX_OUT", "ICMP_TYPE", "ICMP_IPV4_TYPE", "DNS_QUERY_ID", "DNS_QUERY_TYPE",
    "DNS_TTL_ANSWER", "FTP_COMMAND_RET_CODE",
)
PUBLISHED_COLUMNS = (*PUBLISHED_FEATURES, "Label", "Attack")
PUBLISHED_CATEGORIES = {
    "benign": 6_099_469,
    "backdoor": 16_809,
    "dos": 712_609,
    "ddos": 2_026_234,
    "injection": 684_465,
    "mitm": 7_723,
    "password": 1_153_323,
    "ransomware": 3_425,
    "scanning": 3_781_419,
    "xss": 2_455_020,
}
PUBLISHED_LABELS = {"benign": 6_099_469, "attack": 10_841_027}
INPUT = Path("data/level2/nf-ton-iot-v2/NF-ToN-IoT-v2.csv")
ADDRESS_COLUMNS = {"IPV4_SRC_ADDR", "IPV4_DST_ADDR"}
FIELD_MAXIMUMS = {
    "PROTOCOL": 255, "MIN_TTL": 255, "MAX_TTL": 255,
    "L4_SRC_PORT": 65_535, "L4_DST_PORT": 65_535, "Label": 1,
}
FLOW_KEY = Struct(">B5Q")
SEPARATOR = "\x1f"
RECORDS_PER_CHUNK = 4096


@lru_cache(maxsize=4096)
def is_ipv4(token):
    """Reuse address parsing for repeated endpoints without retaining the dataset."""
    try:
        IPv4Address(token)
    except ValueError:
        return False
    return True


class ColumnAudit:
    """Keep bounded type, missing-value, and numeric summaries for one column."""

    def __init__(self, column):
        self.numeric = column in PUBLISHED_COLUMNS and column not in ADDRESS_COLUMNS | {"Attack"}
        self.address = column in ADDRESS_COLUMNS
        self.maximum = FIELD_MAXIMUMS.get(column)
        self.types = Counter()
        self.missing = self.zeros = self.negative = self.nonfinite = self.above_maximum = 0
        self.minimum_value = self.maximum_value = None

    def observe(self, cell, occurrences):
        value = cell.strip()
        if not value:
            self.missing += occurrences
            return
        if not self.numeric:
            kind = "text"
            if self.address:
                kind = "ipv4" if len(value) <= 15 and is_ipv4(value) else "invalid_ipv4"
            self.types[kind] += occurrences
            return
        if value == "0":
            self.types["integer"] += occurrences
            self.zeros += occurrences
            if self.minimum_value is None or self.minimum_value > 0:
                self.minimum_value = 0
            if self.maximum_value is None or self.maximum_value < 0:
                self.maximum_value = 0
            return
        unsigned = value[1:] if value.startswith(("+", "-")) else value
        if unsigned.isascii() and unsigned.isdecimal() and len(value) <= 64:
            number = int(value)
            self.types["integer"] += occurrences
        else:
            try:
                number = float(value)
            except ValueError:
                self.types["invalid_numeric"] += occurrences
                return
            if not isfinite(number):
                self.nonfinite += occurrences
                return
            self.types["decimal"] += occurrences
        if number == 0:
            self.zeros += occurrences
        if number < 0:
            self.negative += occurrences
        if self.maximum is not None and number > self.maximum:
            self.above_maximum += occurrences
        if self.minimum_value is None or number < self.minimum_value:
            self.minimum_value = number
        if self.maximum_value is None or number > self.maximum_value:
            self.maximum_value = number

    def report(self):
        return {
            "observed_types": dict(self.types),
            "missing": self.missing,
            "zeros": self.zeros,
            "negative": self.negative,
            "nonfinite": self.nonfinite,
            "above_expected_maximum": self.above_maximum,
            "numeric_min": self.minimum_value,
            "numeric_max": self.maximum_value,
        }


def raw_row_key(row):
    """Keep exact parsed fields in order, with an unambiguous control-character fallback."""
    joined = SEPARATOR.join(row)
    if joined.count(SEPARATOR) == len(row) - 1:
        return b"\x00" + joined.encode("utf-8")
    return b"\x01" + json.dumps(row, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def record_anomalies(features):
    """Distinguish review signals from invalid inferences about the source."""
    _, duration, forward_packets, reverse_packets, forward_bytes, reverse_bytes = features
    if duration == 0:
        yield "zero_duration"
    if reverse_packets == reverse_bytes == 0:
        yield "zero_reverse_packets_and_octets"
    if forward_packets == reverse_packets == 0:
        yield "zero_packets_both_directions"
    if (forward_packets == 0) != (forward_bytes == 0):
        yield "forward_packet_octet_zero_disagreement"
    if (reverse_packets == 0) != (reverse_bytes == 0):
        yield "reverse_packet_octet_zero_disagreement"


def read_columns(reader):
    columns = next(reader, [])
    if not columns or any(not field or field != field.strip() for field in columns):
        raise ValueError("CSV header is empty or contains a blank or padded column name")
    if len(columns) != len(set(columns)):
        raise ValueError("CSV header contains duplicate columns")
    absent = set((*SOURCE_COLUMNS, "Label", "Attack")).difference(columns)
    if absent:
        raise ValueError(f"CSV is missing required fields: {', '.join(sorted(absent))}")
    return columns


def observe_chunks(reader, counters):
    """Parse each distinct cell spelling once per column and chunk."""
    width = len(counters)
    first_record = 1
    while chunk := list(islice(reader, RECORDS_PER_CHUNK)):
        for index, row in enumerate(chunk, start=first_record):
            if len(row) != width:
                raise ValueError(f"CSV record {index:,} has {len(row)} fields, expected {width}")
        for counter, cells in zip(counters, zip(*chunk)):
            for cell, occurrences in Counter(cells).items():
                counter.observe(cell, occurrences)
        first_record += len(chunk)
        yield from chunk


def prepare_values(values):
    return normalize_flow(dict(zip(SOURCE_COLUMNS, values)))


def scan_rows(reader, columns, raw, vectors, progress):
    counters = {column: ColumnAudit(column) for column in columns}
    positions = {column: index for index, column in enumerate(columns)}
    get_values = itemgetter(*(positions[column] for column in SOURCE_COLUMNS))
    prepare_repeated = lru_cache(maxsize=4096)(prepare_values)
    label_index, attack_index = positions["Label"], positions["Attack"]
    labels = Counter()
    categories = Counter()
    class_category = Counter()
    anomalies = Counter()
    rejections = Counter()
    protocol_counts = Counter()
    total = 0

    for total, row in enumerate(observe_chunks(reader, counters.values()), start=1):
        label_value = row[label_index]
        label = 0 if label_value == "0" else 1 if label_value == "1" else None
        class_name = "benign" if label == 0 else "attack" if label == 1 else "invalid"
        category_value = row[attack_index].strip().casefold()
        category = category_value if category_value in PUBLISHED_CATEGORIES else "unknown"
        if not category_value:
            category = "missing"
        labels[class_name] += 1
        categories[category] += 1
        class_category[class_name, category] += 1
        if category in PUBLISHED_CATEGORIES and label is not None and (label == 0) != (category == "benign"):
            anomalies["binary_category_disagreement"] += 1
        raw.add(raw_row_key(row))
        try:
            values = get_values(row)
            # Avoid retaining unexpectedly large raw tokens in the reuse cache.
            features = prepare_repeated(values) if sum(map(len, values)) <= 128 else prepare_values(values)
        except FlowValidationError as error:
            rejections[f"{error.column}.{error.reason}"] += 1
        else:
            vectors.add(FLOW_KEY.pack(*features), label)
            protocol_counts[features.protocol] += 1
            anomalies.update(record_anomalies(features))
        if progress is not None and total % 250_000 == 0:
            progress(total)

    return {
        "records": total,
        "column_summaries": {column: counter.report() for column, counter in counters.items()},
        "binary_classes": dict(labels),
        "attack_categories": dict(categories),
        "class_by_category": {
            name: {category: count for (row_class, category), count in class_category.items()
                   if row_class == name}
            for name in labels
        },
        "feature_rejections_by_first_error": dict(rejections),
        "protocol_counts": dict(sorted(protocol_counts.items())),
        "row_flags": dict(anomalies),
    }


def audit_dataset(path, *, scratch_parent=None, chunk_bytes=32 * 1024 * 1024, progress=None):
    """Stream the CSV and use temporary sorted runs for exact global grouping."""
    path = Path(path)
    scratch_parent = Path(scratch_parent) if scratch_parent is not None else path.parent
    with (
        path.open("rb") as source,
        ExactGroupCounter(scratch_parent, max_chunk_bytes=chunk_bytes) as raw,
        ExactGroupCounter(scratch_parent, max_chunk_bytes=chunk_bytes) as vectors,
    ):
        original = fstat(source.fileno())
        sha256 = file_digest(source, "sha256").hexdigest()
        source.seek(0)
        with TextIOWrapper(source, encoding="utf-8-sig", newline="") as text:
            reader = csv.reader(text, strict=True)
            columns = read_columns(reader)
            report = scan_rows(reader, columns, raw, vectors, progress)
            scanned = fstat(source.fileno())
        if not report["records"]:
            raise ValueError("CSV contains no records")
        if progress is not None:
            progress(None)
        raw_summary = raw.finish()
        vector_summary = vectors.finish()
    if file_identity(original) != file_identity(scanned) or file_identity(original) != file_identity(path.stat()):
        raise ValueError("Source CSV changed while it was being audited")
    missing_fields = sorted(set(PUBLISHED_COLUMNS).difference(columns))
    additional_fields = sorted(set(columns).difference(PUBLISHED_COLUMNS))
    report.update(
        file_bytes=original.st_size,
        sha256=sha256,
        schema_version=SCHEMA_VERSION,
        columns=columns,
        missing_published_columns=missing_fields,
        additional_columns=additional_fields,
        grouping_metadata_candidates=[
            column for column in additional_fields
            if any(token in column.casefold() for token in ("capture", "time", "session", "flow_id", "scenario", "dataset"))
        ],
        full_rows=asdict(raw_summary),
        common_vectors=asdict(vector_summary),
        matches_published_totals=(
            not missing_fields and not additional_fields
            and report["binary_classes"] == PUBLISHED_LABELS
            and report["attack_categories"] == PUBLISHED_CATEGORIES
        ),
    )
    return report


def file_identity(info):
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--progress", action="store_true", help="Print scan progress to stderr")
    args = parser.parse_args(argv)

    def print_progress(rows):
        if rows is None:
            print("CSV scanned. Merging exact duplicate groups.", file=sys.stderr, flush=True)
        else:
            print(f"Scanned {rows:,} records.", file=sys.stderr, flush=True)

    try:
        report = audit_dataset(INPUT, progress=print_progress if args.progress else None)
    except (OSError, ValueError, csv.Error) as error:
        print(f"Dataset audit failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, allow_nan=False))
    return 0 if report["matches_published_totals"] else 2


if __name__ == "__main__":
    sys.exit(main())
