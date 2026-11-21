"""Read-only native-schema audit of the CNS 2022 corrected CIC-IDS2017 ZIP."""

import csv
from collections import Counter
from contextlib import ExitStack
from dataclasses import asdict
from datetime import date, datetime, timedelta
from functools import lru_cache
from hashlib import file_digest
from io import TextIOWrapper
from ipaddress import ip_address
from itertools import combinations, islice
import json
from math import isfinite
from os import fstat
from pathlib import Path, PurePosixPath
from struct import Struct
import sys
from time import perf_counter
from zipfile import BadZipFile, ZipFile

from ml.audit_level2_data import file_identity, raw_row_key
from ml.level2_audit_storage import ExactGroupCounter
from ml.level2_provenance import CIC_COUNTER_COLUMNS, cic_native_counters


ARCHIVE = Path("data/level2/cicids2017-improved/CICIDS2017_improved.zip")
ARCHIVE_BYTES = 343_549_013
DAYS = ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday")
DATES = tuple(date(2017, 7, day) for day in range(3, 8))
PARTITIONS = {"benign_check": (0,), "fit": (1, 2), "calibration": (3,), "validation": (4,)}
TEXT_COLUMNS = {"Flow ID", "Src IP", "Dst IP", "Timestamp", "Label", "Attempted Category"}
REQUIRED_COLUMNS = {*CIC_COUNTER_COLUMNS, *TEXT_COLUMNS, "Src Port", "Dst Port", "id"}
NATIVE_KEY = Struct(">B5Q")
CHUNK_ROWS = 4096


class ColumnQuality:
    """Aggregate value quality and numeric range while retaining no raw cells."""

    def __init__(self, numeric):
        self.numeric = numeric
        self.counts = Counter()
        self.minimum = self.maximum = None

    def add(self, cell, count):
        value = cell.strip()
        if not value:
            self.counts["blank"] += count
            return
        if not self.numeric:
            self.counts["text"] += count
            return
        try:
            number = int(value)
            form = "integer"
        except ValueError:
            try:
                number = float(value)
            except ValueError:
                self.counts["invalid_numeric"] += count
                return
            if not isfinite(number):
                self.counts["nonfinite"] += count
                return
            form = "decimal"
        self.counts[form] += count
        if number == 0:
            self.counts["zero"] += count
        if number < 0:
            self.counts["negative"] += count
        self.minimum = number if self.minimum is None else min(number, self.minimum)
        self.maximum = number if self.maximum is None else max(number, self.maximum)

    def report(self):
        return {"counts": dict(self.counts), "minimum": self.minimum, "maximum": self.maximum}


class DayGroups:
    """Summarize exact keys across days without retaining the distinct groups."""

    def __init__(self):
        self.key = None
        self.day_rows = {}
        self.benign = self.attacks = 0
        self.groups = self.rows = self.duplicate_rows = self.mixed_groups = self.mixed_rows = 0
        self.largest = self.cross_day_groups = self.cross_day_rows = 0
        self.boundaries = {(left, right): Counter() for left, right in combinations(PARTITIONS, 2)}
        self.boundaries["fit and calibration", "validation"] = Counter()

    def add(self, group):
        key, rows, benign, attacks = group
        identity, day = key[:-1], key[-1]
        if identity != self.key:
            self.finish_group()
            self.key = identity
        self.day_rows[day] = (rows, benign, attacks)
        self.benign += benign
        self.attacks += attacks

    def finish_group(self):
        if not self.day_rows:
            return
        rows = sum(values[0] for values in self.day_rows.values())
        self.rows += rows
        self.groups += 1
        self.largest = max(self.largest, rows)
        if rows > 1:
            self.duplicate_rows += rows
        if self.benign and self.attacks:
            self.mixed_groups += 1
            self.mixed_rows += rows
        if len(self.day_rows) > 1:
            self.cross_day_groups += 1
            self.cross_day_rows += rows
            partition_counts = {}
            for name, days in {**PARTITIONS, "fit and calibration": (1, 2, 3)}.items():
                partition_counts[name] = tuple(
                    sum(self.day_rows.get(day, (0, 0, 0))[i] for day in days) for i in range(3)
                )
            for (left, right), counters in self.boundaries.items():
                left_values, right_values = partition_counts[left], partition_counts[right]
                if left_values[0] and right_values[0]:
                    counters["shared_groups"] += 1
                    for name, value in zip(("rows", "benign", "attacks"), left_values, strict=True):
                        counters[f"left_{name}"] += value
                    for name, value in zip(("rows", "benign", "attacks"), right_values, strict=True):
                        counters[f"right_{name}"] += value
        self.day_rows.clear()
        self.benign = self.attacks = 0

    def report(self):
        self.finish_group()
        return {
            "rows": self.rows, "distinct_groups": self.groups,
            "duplicate_occurrences": self.rows - self.groups, "rows_in_repeated_groups": self.duplicate_rows,
            "largest_group": self.largest, "conflicting_groups": self.mixed_groups,
            "conflicting_rows": self.mixed_rows, "cross_day_groups": self.cross_day_groups,
            "rows_in_cross_day_groups": self.cross_day_rows,
            "boundaries": {
                f"{left} to {right}": {name: counts[name] for name in (
                    "shared_groups", "left_rows", "left_benign", "left_attacks",
                    "right_rows", "right_benign", "right_attacks",
                )}
                for (left, right), counts in self.boundaries.items()
            },
        }


@lru_cache(maxsize=8192)
def address_key(host):
    address = ip_address(host)
    return bytes((address.version,)) + int(address).to_bytes(16, "big")


def tuple_key(source, source_port, destination, destination_port, protocol):
    """Group both directions of the exported tuple, preserving endpoint pairings."""
    left = address_key(source) + int(source_port).to_bytes(2, "big")
    right = address_key(destination) + int(destination_port).to_bytes(2, "big")
    return bytes((protocol,)) + min(left, right) + max(left, right)


def label_policy(label, attempted):
    """Preserve the published label and flag count, using the authors' benign policy."""
    if not label.strip() or not attempted.strip():
        raise ValueError("Missing label or attempted category")
    marked = attempted.strip() != "-1"
    return int(label.strip().casefold() != "benign" and not marked), marked


def timestamp_value(value):
    """Validate the export's naive ISO clock without assigning a time zone."""
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is not None or " " not in value:
        raise ValueError("Expected the archive's naive ISO date and time")
    return parsed


def read_header(reader):
    columns = tuple(next(reader, ()))
    if len(columns) != len(set(columns)) or not all(columns):
        raise ValueError("CSV has duplicate, blank or missing column names")
    if missing := REQUIRED_COLUMNS.difference(columns):
        raise ValueError(f"CSV lacks required field names: {', '.join(sorted(missing))}")
    return columns


def read_rows(reader, quality, width):
    offset = 0
    while rows := list(islice(reader, CHUNK_ROWS)):
        for number, row in enumerate(rows, start=offset + 1):
            if len(row) != width:
                raise ValueError(f"CSV record {number:,} has an unexpected width")
        for profile, values in zip(quality, zip(*rows)):
            for value, count in Counter(values).items():
                profile.add(value, count)
        yield from rows
        offset += len(rows)


def scan_member(reader, columns, day, counters):
    quality = [ColumnQuality(name not in TEXT_COLUMNS) for name in columns]
    offset = {name: i for i, name in enumerate(columns)}
    label_at, attempted_at = offset["Label"], offset["Attempted Category"]
    time_at, id_at = offset["Timestamp"], offset["id"]
    src, src_port, dst, dst_port = (offset[name] for name in ("Src IP", "Src Port", "Dst IP", "Dst Port"))
    protocol_at = offset["Protocol"]
    native_at = tuple(offset[name] for name in CIC_COUNTER_COLUMNS)
    labels, attempted_categories, policy_counts, eligible, issues = (Counter() for _ in range(5))
    hourly = {}
    first = last = previous = latest_end = None
    day_suffix = bytes((day,))
    total = 0

    for total, row in enumerate(read_rows(reader, quality, len(columns)), start=1):
        label, attempted = row[label_at], row[attempted_at]
        labels[label] += 1
        binary, marked = label_policy(label, attempted)
        policy_counts[binary] += 1
        if marked:
            attempted_categories[attempted] += 1
        if row[id_at] == str(total - 1):
            issues["id_equals_zero_based_row_number"] += 1
        elif row[id_at] == str(total):
            issues["id_equals_one_based_row_number"] += 1
        counters["raw"].add(raw_row_key(row[:id_at] + row[id_at + 1:]), binary)

        duration = None
        try:
            native = cic_native_counters(dict(zip(
                CIC_COUNTER_COLUMNS, (row[index] for index in native_at), strict=True,
            )))
        except ValueError:
            issues["invalid_native_counters"] += 1
        else:
            duration = native.duration_us
            eligible[binary] += 1
            counters["native"].add(NATIVE_KEY.pack(*native) + day_suffix, binary)
            if native.duration_us == 0:
                issues["zero_duration"] += 1
            if native.forward_packets + native.reverse_packets == 0:
                issues["zero_total_packets"] += 1

        try:
            key = tuple_key(row[src], row[src_port], row[dst], row[dst_port], int(row[protocol_at]))
        except (ValueError, OverflowError):
            issues["invalid_tuple"] += 1
        else:
            counters["tuple"].add(key + day_suffix, binary)
        flow_id = row[offset["Flow ID"]]
        if flow_id:
            raw_id = flow_id.encode("utf-8")
            counters["flow_id"].add(len(raw_id).to_bytes(4, "big") + raw_id + day_suffix, binary)
        if flow_id == "-".join((row[src], row[dst], row[src_port], row[dst_port], row[protocol_at])):
            issues["flow_id_equals_oriented_tuple"] += 1

        try:
            clock = timestamp_value(row[time_at])
        except ValueError:
            issues["invalid_timestamp"] += 1
            continue
        if clock.date() != DATES[day]:
            issues["timestamp_outside_member_day"] += 1
        if previous is not None and clock < previous:
            issues["timestamp_backsteps_in_file_order"] += 1
        previous = clock
        first = clock if first is None else min(first, clock)
        last = clock if last is None else max(last, clock)
        hour = clock.strftime("%Y-%m-%d %H:00")
        if hour not in hourly:
            hourly[hour] = Counter()
        hourly[hour][binary] += 1
        if duration is not None:
            try:
                end_clock = clock + timedelta(microseconds=duration)
            except OverflowError:
                issues["invalid_clock_plus_duration"] += 1
            else:
                latest_end = end_clock if latest_end is None else max(latest_end, end_clock)
                if end_clock.date() != clock.date():
                    issues["native_end_crosses_clock_day"] += 1
    return {
        "records": total, "raw_labels": dict(labels), "attempted_categories": dict(attempted_categories),
        "policy_counts": dict(policy_counts), "native_eligible": dict(eligible), "issues": dict(issues),
        "native_clock": {
            "first_start": str(first) if first else None, "last_start": str(last) if last else None,
            "latest_end_from_native_duration": str(latest_end) if latest_end else None,
            "hourly_class_counts": {hour: dict(counts) for hour, counts in sorted(hourly.items())},
        },
        "column_quality": {name: profile.report() for name, profile in zip(columns, quality)},
    }


def audit_archive(path, *, chunk_bytes=32 * 1024 * 1024, progress=None):
    """Stream exactly the five daily CSVs, verifying each ZIP member's CRC."""
    path = Path(path)
    member_names = {f"{name.lower()}.csv" for name in DAYS}
    with path.open("rb") as handle, ExitStack() as stack:
        original = fstat(handle.fileno())
        sha256 = file_digest(handle, "sha256").hexdigest()
        handle.seek(0)
        release = stack.enter_context(ZipFile(handle))
        entries = release.infolist()
        if len(entries) != len(member_names) or {entry.filename for entry in entries} != member_names:
            raise ValueError("Archive does not contain exactly the five corrected 2017 CSV members")
        counters = {
            name: stack.enter_context(ExactGroupCounter(path.parent, max_chunk_bytes=chunk_bytes))
            for name in ("raw", "native", "tuple", "flow_id")
        }
        columns = None
        members = {}
        for day, name in enumerate(DAYS):
            member = release.getinfo(f"{name.lower()}.csv")
            if progress is not None:
                progress(f"Auditing {member.filename}")
            with release.open(member) as raw, TextIOWrapper(raw, encoding="utf-8-sig", newline="") as decoded:
                reader = csv.reader(decoded, strict=True)
                header = read_header(reader)
                if columns is not None and columns != header:
                    raise ValueError(f"Different native header in {PurePosixPath(member.filename).name}")
                columns = header
                report = scan_member(reader, columns, day, counters)
            members[name] = {
                "name": member.filename, "bytes": member.file_size, "crc32": f"{member.CRC:08x}", **report,
            }
        duplicates = {"raw_excluding_id": asdict(counters["raw"].finish())}
        for name in ("native", "tuple", "flow_id"):
            if progress is not None:
                progress(f"Merging exact {name} groups")
            aggregate = DayGroups()
            counters[name].finish(on_group=aggregate.add)
            duplicates[name] = aggregate.report()
        if file_identity(original) != file_identity(fstat(handle.fileno())):
            raise ValueError("Archive changed while being scanned")
    if file_identity(original) != file_identity(path.stat()):
        raise ValueError("Archive path changed while being scanned")
    return {
        "bytes": original.st_size, "sha256": sha256, "crc_verified": True, "columns": columns,
        "members": members, "groups": duplicates,
    }


def main():
    started = perf_counter()
    try:
        if ARCHIVE.stat().st_size != ARCHIVE_BYTES:
            raise ValueError("The archive byte count differs from the approved release")
        result = audit_archive(ARCHIVE, progress=lambda line: print(line, file=sys.stderr, flush=True))
    except (BadZipFile, OSError, ValueError, csv.Error) as error:
        print(f"CIC audit failed: {error}", file=sys.stderr)
        return 1
    result["elapsed_seconds"] = round(perf_counter() - started, 3)
    print(json.dumps(result, indent=2, allow_nan=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
