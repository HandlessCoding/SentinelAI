"""Audit and manifest the G19 chronological split without fitting a model."""

from array import array
from collections import Counter
from contextlib import ExitStack
import csv
from datetime import timedelta
from gzip import GzipFile
from hashlib import file_digest
from io import TextIOWrapper
from itertools import combinations
import json
from os import fstat
from pathlib import Path
from shutil import disk_usage
from struct import Struct
import sys
from tempfile import TemporaryDirectory
from time import perf_counter
from zipfile import BadZipFile, ZipFile

from ml.audit_cic_release import (
    ARCHIVE, ARCHIVE_BYTES, DATES, DAYS, NATIVE_KEY, label_policy, read_header,
    timestamp_value, tuple_key,
)
from ml.audit_level2_data import file_identity
from ml.level2_audit_storage import ExactGroupCounter
from ml.level2_provenance import CIC_COUNTER_COLUMNS, cic_native_counters


RELEASE_SHA256 = "97fdb91d339e2d8cf5627f981b831e5e7e400b981c58181c451a38fd03c48883"
MAX_ROWS = 2_200_000
SCRATCH_MIN_BYTES = 2 * 1024 ** 3
CHUNK_BUDGET = 24 * 1024 ** 2
PORTABLE_COLUMNS = CIC_COUNTER_COLUMNS[:4]
PORTABLE_KEY = Struct(">B3Q")
WORD = Struct(">I")
DAY_ROLES = (0, 1, 1, 2, 3)
ROLES = ("monday", "fit", "calibration", "validation")
KEYS = ("native", "portable", "tuple", "flow_id")
BITS = {name: 1 << i for i, name in enumerate(KEYS)}
ALL_KEYS = sum(BITS.values())
SOURCE_FILTERS = {
    "unfiltered": 0, "native_only": BITS["native"],
    "both_vectors": BITS["native"] | BITS["portable"], "all_source_keys": ALL_KEYS,
}
PRIMARY = "all_retained_keys"
POLICIES = (*SOURCE_FILTERS, PRIMARY)
MIN_CLASS_ROWS = 10_000
MIN_CATEGORY_SOURCE_ROWS = 100
ROLE_PAIRS = tuple(combinations(range(1, len(ROLES)), 2))
ROW_MANIFEST = "g19-eligible-rows.csv.gz"
SPLIT_REPORT = "g19-split-manifest.json"


class CrossRoleGroups:
    """Write row-index postings for exact keys occurring in multiple roles."""

    def __init__(self, stream, roles):
        self.stream = stream
        self.roles = roles
        self.key = None
        self.rows = array("I")
        self.roles_mask = 0

    def add(self, group):
        packed = group[0]
        key, index = packed[:-WORD.size], WORD.unpack_from(packed, len(packed) - WORD.size)[0]
        if key != self.key:
            self.flush()
            self.key = key
        self.rows.append(index)
        self.roles_mask |= 1 << self.roles[index]

    def flush(self):
        if self.roles_mask.bit_count() > 1:
            self.stream.write(WORD.pack(len(self.rows)))
            self.rows.tofile(self.stream)
        if self.rows:
            del self.rows[:]
        self.roles_mask = 0


def read_postings(path):
    """Revisit multi-role groups without storing or publishing their raw keys."""
    with path.open("rb") as stream:
        while width := stream.read(WORD.size):
            rows = array("I")
            rows.fromfile(stream, WORD.unpack(width)[0])
            yield rows


def row_keys(row):
    native = cic_native_counters(row)
    endpoint = tuple_key(row["Src IP"], row["Src Port"], row["Dst IP"], row["Dst Port"], native.protocol)
    flow_id = row["Flow ID"].encode("utf-8")
    if not flow_id.strip():
        raise ValueError("Missing exported flow ID")
    keys = (NATIVE_KEY.pack(*native), PORTABLE_KEY.pack(*native[:4]), endpoint,
            WORD.pack(len(flow_id)) + flow_id)
    return keys, native


def scan_release(source, scratch, progress, chunk_bytes):
    """Preserve source order and retain only compact labels, roles and clock aggregates."""
    roles, labels = bytearray(), array("H")
    label_index = {}
    members, headers = [], None
    day_ends = []
    expected = {f"{name.lower()}.csv" for name in DAYS}
    with ZipFile(source) as archive, ExitStack() as stack:
        names = archive.namelist()
        if len(names) != len(expected) or set(names) != expected:
            raise ValueError("Expected exactly the five corrected 2017 CSV members")
        counters = [
            stack.enter_context(ExactGroupCounter(scratch, max_chunk_bytes=chunk_bytes))
            for _ in KEYS
        ]
        for day, name in enumerate(DAYS):
            role = DAY_ROLES[day]
            progress(f"Reading {name}")
            first = last_end = None
            anomalies = Counter()
            begin = len(roles)
            with archive.open(f"{name.lower()}.csv") as raw, TextIOWrapper(
                raw, encoding="utf-8-sig", newline="",
            ) as decoded:
                reader = csv.reader(decoded, strict=True)
                columns = read_header(reader)
                if headers is not None and columns != headers:
                    raise ValueError(f"{name} has a different native CSV header")
                headers = columns
                for ordinal, values in enumerate(reader, 1):
                    try:
                        row = dict(zip(columns, values, strict=True))
                        keys, native = row_keys(row)
                        clock = timestamp_value(row["Timestamp"])
                        end = clock + timedelta(microseconds=native.duration_us)
                        if clock.date() != DATES[day] or end.date() != DATES[day]:
                            raise ValueError("Flow start or end is outside the published capture day")
                        binary, attempted = label_policy(row["Label"], row["Attempted Category"])
                    except (ValueError, OverflowError) as error:
                        raise ValueError(f"Invalid required field or clock in {name} record {ordinal:,}") from error
                    if len(roles) >= MAX_ROWS:
                        raise ValueError("Release exceeds the row safety limit")
                    first = clock if first is None else min(first, clock)
                    last_end = end if last_end is None else max(last_end, end)
                    anomalies["zero_duration"] += native.duration_us == 0
                    anomalies["zero_forward_packets"] += native.forward_packets == 0
                    anomalies["protocol_zero"] += native.protocol == 0
                    suffix = WORD.pack(len(roles))
                    roles.append(role)
                    group = (row["Label"], binary, attempted)
                    labels.append(label_index.setdefault(group, len(label_index)))
                    for counter, key in zip(counters, keys, strict=True):
                        counter.add(key + suffix)
            if first is None or (day_ends and first <= day_ends[-1]):
                raise ValueError(f"{name} is empty or overlaps the previous capture day's clock")
            day_ends.append(last_end)
            members.append({
                "member": f"{name.lower()}.csv", "role": ROLES[role],
                "rows": len(roles) - begin, "start": first.isoformat(sep=" "),
                "end": last_end.isoformat(sep=" "), "anomalies": dict(anomalies),
            })

        for name, counter in zip(KEYS, counters, strict=True):
            progress(f"Sorting exact {name} keys")
            with (scratch / name).open("wb") as stream:
                postings = CrossRoleGroups(stream, roles)
                counter.finish(on_group=postings.add)
                postings.flush()
    return roles, labels, tuple(label_index), members


def overlap_flags(scratch, roles):
    """Compute source and retained-history matches using keys and roles only."""
    source = bytearray(len(roles))
    for name, bit in BITS.items():
        for rows in read_postings(scratch / name):
            first_dev = next((roles[index] for index in rows if roles[index]), None)
            if first_dev is not None:
                for index in rows:
                    if roles[index] == 0 or roles[index] > first_dev:
                        source[index] |= bit

    # The first two development stages are identical between all-source and
    # retained-history rules. Recompute Friday matches using retained Thursday.
    retained = source.copy()
    for index, role in enumerate(roles):
        if role == 3:
            retained[index] = 0
    for name, bit in BITS.items():
        for rows in read_postings(scratch / name):
            earlier = any(roles[index] == 1 or (roles[index] == 2 and source[index] == 0)
                          for index in rows)
            if earlier:
                for index in rows:
                    if roles[index] == 3:
                        retained[index] |= bit
    return source, retained


def inclusion(policy, role, source_flag, retained_flag):
    if role == 0:
        return False
    if policy == PRIMARY:
        return retained_flag == 0
    return source_flag & SOURCE_FILTERS[policy] == 0


def audit_cohorts(scratch, roles, source, retained):
    """Independently count overlapping exact groups in every kept role pair."""
    pairs = {
        policy: {
            f"{ROLES[left]}_to_{ROLES[right]}": dict.fromkeys(KEYS, 0)
            for left, right in ROLE_PAIRS
        }
        for policy in POLICIES
    }
    for name in KEYS:
        for rows in read_postings(scratch / name):
            kept = dict.fromkeys(POLICIES, 0)
            for index in rows:
                role = roles[index]
                if role:
                    for policy in POLICIES:
                        if inclusion(policy, role, source[index], retained[index]):
                            kept[policy] |= 1 << role
            for policy, role_mask in kept.items():
                for left, right in ROLE_PAIRS:
                    pair_mask = (1 << left) | (1 << right)
                    if role_mask & pair_mask == pair_mask:
                        pairs[policy][f"{ROLES[left]}_to_{ROLES[right]}"][name] += 1
    return pairs


def summarize(roles, labels, categories, source, retained):
    counters = {policy: [Counter() for _ in ROLES] for policy in POLICIES}
    matches = {rule: [Counter() for _ in ROLES] for rule in ("source", "retained")}
    monday = Counter()
    for role, label, raw, kept in zip(roles, labels, source, retained, strict=True):
        counters["unfiltered"][role][label] += 1
        if not role:
            monday[raw] += 1
            continue
        matches["source"][role][raw] += 1
        matches["retained"][role][kept] += 1
        for policy in POLICIES[1:]:
            if inclusion(policy, role, raw, kept):
                counters[policy][role][label] += 1

    def support(counts):
        benign = attack = attempted_rows = 0
        attack_categories = Counter()
        raw_labels = Counter()
        for index, count in counts.items():
            label, binary, attempted = categories[index]
            attack += count * binary
            benign += count * (1 - binary)
            attempted_rows += count * attempted
            raw_labels[label] += count
            if binary:
                attack_categories[label] += count
        return {"rows": benign + attack, "benign": benign, "attack": attack,
                "attempted": attempted_rows, "attack_categories": dict(attack_categories),
                "raw_labels": dict(raw_labels)}

    stats = {
        policy: {ROLES[i]: support(counts) for i, counts in enumerate(by_role)
                 if i or policy == "unfiltered"}
        for policy, by_role in counters.items()
    }
    return stats, {rule: dict(zip(ROLES[1:], counts[1:], strict=True)) for rule, counts in matches.items()}, monday


def feasibility(cohorts, residual):
    """Apply the prespecified half-retention and minimum-support gates."""
    failures = []
    for pair, counts in residual[PRIMARY].items():
        for key, count in counts.items():
            if count:
                failures.append({"boundary": pair, "key": key, "overlapping_groups": count})
    for name, after in cohorts[PRIMARY].items():
        before = cohorts["unfiltered"][name]
        for label in ("benign", "attack"):
            if after[label] < MIN_CLASS_ROWS or 2 * after[label] < before[label]:
                failures.append({"role": name, "class": label, "source": before[label], "kept": after[label]})
        for label, count in before["attack_categories"].items():
            kept = after["attack_categories"].get(label, 0)
            if count >= MIN_CATEGORY_SOURCE_ROWS and 2 * kept < count:
                failures.append({"role": name, "category": label, "source": count, "kept": kept})
    return failures


def write_rows(path, roles, members, source, retained):
    """Write deterministic eligibility by one-based CSV record number."""
    with path.open("wb") as raw, GzipFile(fileobj=raw, mode="wb", filename="", mtime=0) as gz, TextIOWrapper(
        gz, encoding="utf-8", newline="",
    ) as stream:
        writer = csv.writer(stream, lineterminator="\n")
        writer.writerow(("member", "record", "role", "primary_eligible", "source_overlap_bits", "primary_overlap_bits"))
        i = 0
        for member in members:
            for ordinal in range(1, member["rows"] + 1):
                writer.writerow((member["member"], ordinal, member["role"],
                                 int(inclusion(PRIMARY, roles[i], source[i], retained[i])),
                                 source[i], retained[i]))
                i += 1


def digest(path):
    with path.open("rb") as stream:
        return file_digest(stream, "sha256").hexdigest()


def audit_split(path, output, *, expected_sha256, progress=print, chunk_bytes=CHUNK_BUDGET):
    started = perf_counter()
    output.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(dir=output, prefix="g19-scratch-") as temporary:
        scratch = Path(temporary)
        with path.open("rb") as stream:
            initial = file_identity(fstat(stream.fileno()))
            sha256 = file_digest(stream, "sha256").hexdigest()
            if sha256 != expected_sha256:
                raise ValueError("Source SHA-256 differs from the declared release")
            roles, labels, categories, members = scan_release(stream, scratch, progress, chunk_bytes)
            if initial != file_identity(fstat(stream.fileno())) or initial != file_identity(path.stat()):
                raise ValueError("Source archive changed during the audit")
        progress("Measuring source overlap and retained-history overlap")
        source, retained = overlap_flags(scratch, roles)
        progress("Verifying retained partition isolation and support")
        residual = audit_cohorts(scratch, roles, source, retained)
        cohorts, masks, monday = summarize(roles, labels, categories, source, retained)
        failures = feasibility(cohorts, residual)
        rows_path = scratch / ROW_MANIFEST
        write_rows(rows_path, roles, members, source, retained)
        report = {
            "protocol": "g19-chronological-v1",
            "archive": {"name": path.name, "sha256": sha256, "crc_verified": True},
            "members": members, "verified_session_id_available": False,
            "features": {"native": CIC_COUNTER_COLUMNS, "portable": PORTABLE_COLUMNS},
            "overlap_bits": BITS, "source_filter_masks": SOURCE_FILTERS, "primary_policy": PRIMARY,
            "overlap_mask_counts": masks, "monday_source_overlap_mask_counts": monday,
            "cohorts": cohorts, "overlapping_groups": residual,
            "gates": {"minimum_class_rows": MIN_CLASS_ROWS, "minimum_class_retention_fraction": 0.5,
                      "minimum_category_retention_fraction": 0.5,
                      "minimum_source_category_rows_for_gate": MIN_CATEGORY_SOURCE_ROWS},
            "training_allowed": not failures, "failures": failures,
            "row_manifest": {"name": ROW_MANIFEST, "sha256": digest(rows_path)},
            "elapsed_seconds": round(perf_counter() - started, 3),
        }
        report_path = scratch / SPLIT_REPORT
        report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        rows_path.replace(output / ROW_MANIFEST)
        report_path.replace(output / SPLIT_REPORT)
    return report


def main():
    try:
        if ARCHIVE.stat().st_size != ARCHIVE_BYTES:
            raise ValueError("Unexpected corrected 2017 archive size")
        if disk_usage(ARCHIVE.parent).free < SCRATCH_MIN_BYTES:
            raise ValueError("At least 2 GiB of free space is required beside the archive")
        report = audit_split(ARCHIVE, ARCHIVE.parent, expected_sha256=RELEASE_SHA256,
                             progress=lambda message: print(message, file=sys.stderr, flush=True))
    except (OSError, ValueError, BadZipFile, csv.Error) as error:
        print(f"Chronological audit failed: {error}", file=sys.stderr)
        return 1
    print(f"G19 manifest written. Training allowed: {report['training_allowed']}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
