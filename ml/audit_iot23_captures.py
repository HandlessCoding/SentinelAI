"""Read-only Zeek connection audit for individually pinned IoT-23 files."""

import argparse
from collections import Counter, defaultdict
from contextlib import ExitStack
from dataclasses import dataclass
from hashlib import file_digest
import json
from itertools import combinations
from os import fstat
from pathlib import Path
import re
from struct import Struct
import sys

from ml.audit_cic_release import tuple_key
from ml.audit_level2_data import file_identity, raw_row_key
from ml.level2_audit_storage import ExactGroupCounter


ROLES = ("fit", "calibration", "comparison", "validation")
FEATURES = ("proto", "duration", "orig_pkts", "resp_pkts", "orig_ip_bytes", "resp_ip_bytes")
REQUIRED = {*FEATURES, "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "label"}
DETAILED_LABELS = {"detailed-label", "detailed_label", "detailedlabel"}
PROTOCOLS = {"tcp": 6, "udp": 17}
KEYS = ("record", "scoped_uid", "vector", "vector_without_bytes", "tuple", "tuple_at_start")
MAX_BYTES = 512 * 1024 * 1024
MIN_CLASS_ROWS = 1000
MIN_CATEGORY_ROWS = 100
SECONDS = re.compile(r"([0-9]{1,10})(?:\.([0-9]{1,9}))?", re.ASCII)
UINT = re.compile(r"[0-9]{1,20}", re.ASCII)
RULE_FIELD = re.compile(r"!?([A-Za-z][A-Za-z0-9_.]*)\s*[!<>]?=")
LABEL_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_-]*")
COUNTERS = Struct(">B5Q")
UINT64_MAX = (1 << 64) - 1


@dataclass(frozen=True)
class Capture:
    capture_id: str
    original_group: str
    device_group: str | None
    role: str
    log: str
    sha256: str
    negative_evidence: str | None = None
    label_rules: str | None = None
    label_rules_sha256: str | None = None


def nanoseconds(value):
    """Convert decimal Zeek seconds exactly without floating-point grouping."""
    parsed = SECONDS.fullmatch(value)
    if not parsed:
        raise ValueError("malformed seconds")
    whole, fraction = parsed.groups()
    return int(whole) * 10**9 + int((fraction or "").ljust(9, "0"))


def unsigned(value, maximum=UINT64_MAX):
    if not UINT.fullmatch(value) or (number := int(value)) > maximum:
        raise ValueError("malformed counter")
    return number


def detail_column(fields):
    aliases = DETAILED_LABELS.intersection(fields)
    if not REQUIRED.issubset(fields) or len(aliases) != 1 or len(set(fields)) != len(fields):
        raise ValueError("unexpected labeled connection-log fields")
    return aliases.pop()


def log_rows(stream):
    """Return the declared columns, types, missing markers and a row iterator."""
    markers = {"", "-", "(empty)"}
    fields = types = None
    for line in stream:
        line = line.rstrip("\r\n")
        directive, _, value = line.partition(" ")
        if directive == "#separator" and value != r"\x09":
            raise ValueError("expected a Zeek tab-separated log")
        if line.startswith(("#unset_field\t", "#empty_field\t")):
            markers.add(line.split("\t", 1)[1])
        if line.startswith("#fields\t"):
            fields = line.split("\t")[1:]
        if line.startswith("#types\t"):
            types = line.split("\t")[1:]
            break
        if line and not line.startswith("#"):
            raise ValueError("connection records appeared before the schema")
    if fields is None or types is None or len(fields) != len(types):
        raise ValueError("missing or inconsistent Zeek header")

    def rows():
        for line in stream:
            if line.startswith(("#fields\t", "#types\t", "#separator ")):
                raise ValueError("unexpected second Zeek schema")
            if line.startswith("#") or not line.strip():
                continue
            values = line.rstrip("\r\n").split("\t")
            yield values if len(values) == len(fields) else None

    return fields, types, markers, rows()


class Overlap:
    """Count repeated keys by capture and shared keys across each role pair."""

    def __init__(self, captures):
        self.captures = captures
        self.previous = None
        self.parts = {}
        self.duplicate_occurrences = Counter()
        self.boundaries = {f"{left} to {right}": Counter() for left, right in combinations(ROLES, 2)}

    def add(self, group):
        packed, rows, benign, malicious = group
        key, capture_index = packed[:-1], packed[-1]
        if key != self.previous:
            self.finish_key()
            self.previous = key
        capture = self.captures[capture_index]
        self.duplicate_occurrences[capture.capture_id] += rows - 1
        counts = self.parts.setdefault(capture.role, Counter())
        counts.update(rows=rows, verified_benign=benign, explicit_malicious=malicious)

    def finish_key(self):
        if len(self.parts) > 1:
            for left, right in combinations(ROLES, 2):
                if left in self.parts and right in self.parts:
                    counts = self.boundaries[f"{left} to {right}"]
                    counts["keys"] += 1
                    for side, role in (("left", left), ("right", right)):
                        counts.update({f"{side}_{key}": n for key, n in self.parts[role].items()})
        self.parts.clear()

    def report(self):
        self.finish_key()
        return {
            "duplicate_occurrences_by_capture": dict(self.duplicate_occurrences),
            "shared_between_roles": self.boundaries,
        }


def framed_key(values):
    key = raw_row_key(values)
    return len(key).to_bytes(4, "big") + key


def inspect_label_rules(path, expected_digest):
    """Verify a NetflowLabeler sidecar and summarize predicates without their values."""
    definitions, conditions, fields = Counter(), Counter(), defaultdict(Counter)
    label = None
    with path.open("rb") as source:
        stat = fstat(source.fileno())
        digest = file_digest(source, "sha256").hexdigest()
        if digest != expected_digest:
            raise ValueError("Label-rule SHA-256 does not match")
        source.seek(0)
        for ordinal, raw in enumerate(source, 1):
            line = raw.decode("utf-8-sig").strip()
            if not line or line.startswith("#"):
                continue
            if not line.startswith("-"):
                label = line.rstrip(":").split(",", 1)[0].strip()
                if not LABEL_NAME.fullmatch(label):
                    raise ValueError(f"Invalid label declaration at rule line {ordinal}")
                definitions[label] += 1
                continue
            predicates = [RULE_FIELD.match(part.strip()) for part in line[1:].split("&")]
            if label is None or any(match is None for match in predicates):
                raise ValueError(f"Unrecognized predicate at rule line {ordinal}")
            conditions[label] += 1
            fields[label].update(match.group(1).casefold() for match in predicates)
        if file_identity(stat) != file_identity(fstat(source.fileno())):
            raise ValueError("Label rules changed while scanning")
    if not conditions:
        raise ValueError("Label-rule file contains no conditions")
    return {"sha256": digest, "bytes": stat.st_size, "label_sections": definitions,
            "condition_lines": conditions, "predicate_fields": dict(fields)}


def add_keys(row, clock, missing, counters, suffix, label, quality):
    values = []
    for name in FEATURES[1:]:
        if name in missing:
            values.append(None)
            continue
        parser = nanoseconds if name == "duration" else unsigned
        try:
            values.append(parser(row[name]))
        except ValueError:
            quality[f"invalid_{name}"] += 1
            values.append(None)
    protocol = PROTOCOLS.get(row["proto"])
    if protocol is None:
        quality["outside_tcp_udp_contract"] += 1
        return False
    if values[0] == 0:
        quality["zero_duration"] += 1
    if values[2] == 0:
        quality["zero_response_packets"] += 1
    if None not in values[:3]:
        vector = COUNTERS.pack(protocol, *values[:3], 0, 0)
        counters["vector_without_bytes"].add(vector + suffix, label)
    if None not in values:
        counters["vector"].add(COUNTERS.pack(protocol, *values) + suffix, label)

    try:
        key = tuple_key(row["id.orig_h"], unsigned(row["id.orig_p"], 65_535),
                        row["id.resp_h"], unsigned(row["id.resp_p"], 65_535), protocol)
    except ValueError:
        quality["invalid_tuple"] += 1
        return False
    counters["tuple"].add(key + suffix, label)
    if clock is not None:
        counters["tuple_at_start"].add(key + clock.to_bytes(8, "big") + suffix, label)
    return None not in values and clock is not None and "uid" not in missing


def scan_log(path, capture, counters, index):
    with path.open("rb") as source:
        initial = file_identity(fstat(source.fileno()))
        digest = file_digest(source, "sha256").hexdigest()
        if digest != capture.sha256:
            raise ValueError(f"{capture.capture_id} SHA-256 does not match")
    suffix = bytes((index,))
    raw, classes, eligible, missing, quality = (Counter() for _ in range(5))
    categories, eligible_categories, protocols = Counter(), Counter(), Counter()
    protocols_by_class = defaultdict(Counter)
    first = last = None
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        if file_identity(fstat(stream.fileno())) != initial:
            raise ValueError(f"{capture.capture_id} changed before scanning")
        fields, types, markers, rows = log_rows(stream)
        detailed = detail_column(fields)
        for values in rows:
            quality["records"] += 1
            if values is None:
                quality["malformed_width"] += 1
                continue
            row = dict(zip(fields, values, strict=True))
            absent = {name for name, value in row.items() if value in markers}
            missing.update(absent)
            token = row["label"].casefold() if "label" not in absent else ""
            label = None
            if token == "malicious":
                label = 1
            if token == "benign" and capture.negative_evidence:
                label = 0
            class_name = {0: "verified_benign", 1: "explicit_malicious"}.get(label)
            class_name = class_name or ("unverified_benign" if token == "benign" else "unknown")
            raw[row["label"]] += 1
            classes[class_name] += 1
            category = row[detailed] if detailed not in absent else "(unclassified)"
            if label == 1:
                categories[category] += 1
            protocols[row["proto"]] += 1
            protocols_by_class[class_name][row["proto"]] += 1
            clock = None
            try:
                clock = nanoseconds(row["ts"])
            except ValueError:
                quality["invalid_start_time"] += 1
            else:
                first = clock if first is None else min(first, clock)
                last = clock if last is None else max(last, clock)
            counters["record"].add(framed_key(values) + suffix, label)
            if "uid" not in absent:
                counters["scoped_uid"].add(framed_key((capture.original_group, row["uid"])) + suffix, label)
            if add_keys(row, clock, absent, counters, suffix, label, quality) and label is not None:
                eligible[class_name] += 1
                if label == 1:
                    eligible_categories[category] += 1
        if file_identity(fstat(stream.fileno())) != initial or file_identity(path.stat()) != initial:
            raise ValueError(f"{capture.capture_id} changed while scanning")
    return {
        "capture_id": capture.capture_id, "original_group": capture.original_group,
        "device_group": capture.device_group, "role": capture.role, "sha256": digest,
        "bytes": path.stat().st_size, "fields": dict(zip(fields, types, strict=True)),
        "first_start_unix_ns": first, "last_start_unix_ns": last,
        "raw_labels": raw, "classes": classes, "eligible": eligible,
        "categories": categories, "eligible_categories": eligible_categories,
        "protocols": protocols, "protocols_by_class": dict(protocols_by_class),
        "missing": missing, "quality": quality,
    }


def coverage(captures, summaries):
    by_role = {role: Counter() for role in ROLES}
    failures = []
    for attribute in ("original_group", "device_group"):
        roles = defaultdict(set)
        for capture in captures:
            value = getattr(capture, attribute)
            if value is not None:
                roles[value].add(capture.role)
        failures.extend(f"{attribute} {value} crosses roles" for value, group in roles.items() if len(group) > 1)

    validation_positive = set()
    for role in ROLES:
        source, source_categories, eligible_categories = Counter(), Counter(), Counter()
        for capture in summaries:
            if capture["role"] != role:
                continue
            by_role[role].update(capture["eligible"])
            source.update(capture["classes"])
            source_categories.update(capture["categories"])
            eligible_categories.update(capture["eligible_categories"])
            if role == "validation" and capture["eligible"]["explicit_malicious"]:
                validation_positive.add(capture["original_group"])
        for name in ("verified_benign", "explicit_malicious"):
            kept = by_role[role][name]
            if kept < MIN_CLASS_ROWS or 2 * kept < source[name]:
                failures.append(f"{role} has inadequate eligible {name} support")
        for category, count in source_categories.items():
            if category != "(unclassified)" and count >= MIN_CATEGORY_ROWS and 2 * eligible_categories[category] < count:
                failures.append(f"{role} retains fewer than half of {category}")
    if len(validation_positive) < 2:
        failures.append("validation has fewer than two original capture groups with eligible attacks")
    return by_role, failures


def audit(manifest, *, chunk_bytes=16 * 1024 * 1024):
    root = manifest.resolve().parent
    captures = [Capture(**entry) for entry in json.loads(manifest.read_text(encoding="utf-8-sig"))]
    if not 1 <= len(captures) <= 255 or len({item.capture_id for item in captures}) != len(captures):
        raise ValueError("expected 1 to 255 uniquely named capture entries")
    paths = [(root / item.log).resolve() for item in captures]
    rule_paths = []
    for capture, path in zip(captures, paths, strict=True):
        if capture.role not in ROLES or not capture.original_group:
            raise ValueError("unknown role or missing original group")
        if not path.is_relative_to(root) or path.suffix != ".labeled":
            raise ValueError("each log must be a .labeled file inside the local manifest directory")
        if bool(capture.label_rules) != bool(capture.label_rules_sha256):
            raise ValueError("each label-rule file needs a pinned SHA-256")
        rule_path = (root / capture.label_rules).resolve() if capture.label_rules else None
        if rule_path is not None and (not rule_path.is_relative_to(root) or rule_path.suffix != ".config"):
            raise ValueError("each label-rule file must be a .config inside the local manifest directory")
        rule_paths.append(rule_path)
    input_paths = {*paths, *(path for path in rule_paths if path is not None)}
    if len(set(paths)) != len(paths) or sum(path.stat().st_size for path in input_paths) > MAX_BYTES:
        raise ValueError("capture logs repeat or audit inputs exceed 512 MiB")
    rules = [inspect_label_rules(path, capture.label_rules_sha256) if path is not None else None
             for capture, path in zip(captures, rule_paths, strict=True)]
    summaries, overlap_reports = [], {}
    with ExitStack() as stack:
        counters = {name: stack.enter_context(ExactGroupCounter(root, max_chunk_bytes=chunk_bytes)) for name in KEYS}
        for index, (capture, path, rule_report) in enumerate(zip(captures, paths, rules, strict=True)):
            summary = scan_log(path, capture, counters, index)
            summary["label_rules"] = rule_report
            summaries.append(summary)
        for name, counter in counters.items():
            overlap = Overlap(captures)
            counter.finish(on_group=overlap.add)
            overlap_reports[name] = overlap.report()
    by_role, failures = coverage(captures, summaries)
    for key in ("record", "tuple_at_start"):
        for boundary, counts in overlap_reports[key]["shared_between_roles"].items():
            if counts["keys"]:
                failures.append(f"{boundary} requires review of shared {key} keys")
    return {"cohorts": by_role, "captures": summaries, "overlap": overlap_reports,
            "automatic_failures": failures, "requires_provenance_and_label_review": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    args = parser.parse_args()
    try:
        result = audit(args.manifest)
    except (OSError, TypeError, ValueError) as error:
        print(f"IoT-23 audit failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
