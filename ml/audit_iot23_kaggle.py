"""Read-only capture feasibility checks for the bounded G24 IoT-23 CSV cohort."""

from collections import Counter
from contextlib import ExitStack
import csv
from dataclasses import dataclass
from hashlib import sha256
import json
from os import fstat
from pathlib import Path
from struct import Struct
import sys

from ml.audit_cic_release import tuple_key
from ml.audit_iot23_captures import (
    MIN_CATEGORY_ROWS, MIN_CLASS_ROWS, PROTOCOLS, ROLES, Overlap, nanoseconds, unsigned,
)
from ml.audit_level2_data import file_identity
from ml.level2_audit_storage import ExactGroupCounter


DATA = Path("data/level2/iot23-kaggle")
PINS = Path("data/level2/iot23-kaggle-audit")
COLUMNS = (
    "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service",
    "duration", "orig_bytes", "resp_bytes", "conn_state", "local_orig", "local_resp",
    "missed_bytes", "history", "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes",
    "tunnel_parents   label   detailed-label",
)
FEATURES = ("proto", "orig_pkts", "resp_pkts", "orig_ip_bytes", "resp_ip_bytes")
COUNTER_COLUMNS = (16, 18, 17, 19)
VECTOR = Struct(">B4Q")
MISSING = {"", "-", "(empty)"}
KEYS = ("vector", "tuple", "tuple_at_start")
MAX_BYTES = 200 * 1024 * 1024


@dataclass(frozen=True)
class Capture:
    number: int
    capture_id: str
    role: str
    benign_only: bool = False


# Fixed before the feature and overlap scan. The roles refer to preflight only.
CAPTURES = (
    Capture(1, "CTU-Honeypot-Capture-4-1", "fit", True),
    Capture(23, "CTU-IoT-Malware-Capture-1-1", "fit"),
    Capture(2, "CTU-Honeypot-Capture-5-1", "calibration", True),
    Capture(5, "CTU-IoT-Malware-Capture-8-1", "calibration"),
    Capture(19, "CTU-IoT-Malware-Capture-3-1", "comparison"),
    Capture(3, "CTU-Honeypot-Capture-7-1", "validation", True),
    Capture(13, "CTU-IoT-Malware-Capture-42-1", "validation"),
    Capture(17, "CTU-IoT-Malware-Capture-34-1", "validation"),
)


def unpack_label(cell):
    """Decode the combined field after CSV parsing, preserving compound categories."""
    parts = cell.split("   ", 2)
    if len(parts) != 3:
        raise ValueError("expected tunnel, binary label and detailed label")
    label = parts[1].strip().casefold()
    detail = parts[2].strip()
    return {"benign": 0, "malicious": 1}.get(label), detail


def source_lines(source, digest):
    for line in source:
        digest.update(line)
        yield line.decode("utf-8")


class CohortOverlap(Overlap):
    """Add global vector counts and a development-versus-validation diagnostic."""

    def __init__(self, captures):
        super().__init__(captures)
        self.global_counts = Counter()
        self.validation_shared = Counter()

    def finish_key(self):
        if self.parts:
            all_rows = sum(self.parts.values(), Counter())
            self.global_counts["keys"] += 1
            if all_rows["rows"] > 1:
                self.global_counts["repeated_rows"] += all_rows["rows"]
            if all_rows["verified_benign"] and all_rows["explicit_malicious"]:
                self.global_counts["label_conflict_keys"] += 1
                self.global_counts["rows_in_label_conflict"] += all_rows["rows"]
            if "validation" in self.parts and len(self.parts) > 1:
                self.validation_shared.update(self.parts["validation"])
                self.validation_shared["keys"] += 1
        super().finish_key()

    def report(self):
        result = super().report()
        result.update(global_counts=self.global_counts, validation_shared=self.validation_shared)
        # The underlying utility names the negative column for reviewed negatives.
        # Here it summarizes publisher/CSV labels, whose review is unresolved.
        for counts in (*result["shared_between_roles"].values(), self.validation_shared):
            for key in tuple(counts):
                if key.endswith("verified_benign"):
                    counts[key.replace("verified_benign", "benign_labeled")] = counts.pop(key)
        return result


def scan_capture(path, pinned_sha, capture, index, counters):
    digest = sha256()
    suffix = bytes((index,))
    observed, eligible, timed, issues = (Counter() for _ in range(4))
    categories, retained_categories, timed_categories = (Counter() for _ in range(3))
    protocols = {name: Counter() for name in ("benign", "malicious", "unknown")}
    first = last = None
    with path.open("rb") as source:
        initial = file_identity(fstat(source.fileno()))
        reader = csv.reader(source_lines(source, digest), strict=True)
        if tuple(next(reader, ())) != COLUMNS:
            raise ValueError(f"{path.name} has an unexpected CSV header")
        for row in reader:
            issues["records"] += 1
            if len(row) != len(COLUMNS):
                issues["malformed_width"] += 1
                continue
            try:
                label, category = unpack_label(row[-1])
            except ValueError:
                issues["malformed_labels"] += 1
                continue
            name = ("benign", "malicious")[label] if label is not None else "unknown"
            observed[name] += 1
            if label == 1:
                categories[category] += 1
            protocols[name][row[6]] += 1
            clock = duration = None
            try:
                clock = nanoseconds(row[0])
            except ValueError:
                issues["invalid_timestamp"] += 1
            if clock is not None:
                first = clock if first is None else min(first, clock)
                last = clock if last is None else max(last, clock)
            if row[8] in MISSING:
                issues[f"duration_unset_{name}"] += 1
            else:
                try:
                    duration = nanoseconds(row[8])
                except ValueError:
                    issues[f"duration_invalid_{name}"] += 1

            protocol = PROTOCOLS.get(row[6])
            if protocol is None:
                issues[f"protocol_outside_tcp_udp_{name}"] += 1
                continue
            try:
                endpoint = tuple_key(row[2], unsigned(row[3], 65_535), row[4], unsigned(row[5], 65_535), protocol)
            except ValueError:
                issues["invalid_tuple"] += 1
            else:
                counters["tuple"].add(endpoint + suffix, label)
                if clock is not None:
                    counters["tuple_at_start"].add(endpoint + clock.to_bytes(8, "big") + suffix, label)

            try:
                vector = VECTOR.pack(protocol, *(unsigned(row[column]) for column in COUNTER_COLUMNS))
            except ValueError:
                issues[f"invalid_or_unset_counter_{name}"] += 1
                continue
            counters["vector"].add(vector + suffix, label)
            if label is None:
                continue
            eligible[name] += 1
            if label == 1:
                retained_categories[category] += 1
            if duration is not None:
                timed[name] += 1
                if label == 1:
                    timed_categories[category] += 1
        if initial != file_identity(fstat(source.fileno())) or initial != file_identity(path.stat()):
            raise ValueError(f"{path.name} changed during the audit")
    if digest.hexdigest() != pinned_sha:
        raise ValueError(f"{path.name} differs from its pinned SHA-256")
    return {
        "capture_id": capture.capture_id, "role": capture.role, "sha256": pinned_sha,
        "first_start_unix_ns": first, "last_start_unix_ns": last,
        "observed": observed, "eligible_duration_free": eligible, "eligible_duration_required": timed,
        "attack_categories": categories, "duration_free_categories": retained_categories,
        "duration_required_categories": timed_categories,
        "dedicated_benign_eligible": eligible["benign"] if capture.benign_only else 0,
        "protocols": protocols, "issues": issues,
    }


def assess_roles(captures):
    aggregates = {role: {} for role in ROLES}
    gates = {variant: [] for variant in ("duration_free", "duration_required")}
    for role, stats in aggregates.items():
        subset = [row for row in captures.values() if row["role"] == role]
        for key in ("observed", "eligible_duration_free", "eligible_duration_required",
                    "attack_categories", "duration_free_categories", "duration_required_categories"):
            stats[key] = sum((row[key] for row in subset), Counter())
        stats["dedicated_benign_eligible"] = sum(row["dedicated_benign_eligible"] for row in subset)
        for variant, failures in gates.items():
            kept = stats[f"eligible_{variant}"]
            for label in ("benign", "malicious"):
                if kept[label] < MIN_CLASS_ROWS or 2 * kept[label] < stats["observed"][label]:
                    failures.append(f"{role} lacks {label} label support for {variant}")
            for category, count in stats["attack_categories"].items():
                if count >= MIN_CATEGORY_ROWS and 2 * stats[f"{variant}_categories"][category] < count:
                    failures.append(f"{role} lacks eligible support for category {category}")
            if role == "validation" and sum(row[f"eligible_{variant}"]["malicious"] > 0 for row in subset) < 2:
                failures.append("validation has fewer than two original groups with eligible attacks")
    return aggregates, gates


def audit(data_dir, scratch, pins, *, captures=CAPTURES, chunk_bytes=16 * 1024**2, progress=None):
    paths = {item.number: data_dir / f"dataset{item.number}.csv" for item in captures}
    if len(paths) != len(captures) or len({item.capture_id for item in captures}) != len(captures):
        raise ValueError("each original capture and file must be assigned once")
    available = {number: path for number, path in paths.items() if path.is_file()}
    if sum(path.stat().st_size for path in available.values()) > MAX_BYTES:
        raise ValueError("selected capture inputs exceed 200 MiB")
    missing = {paths[item.number].name: {"capture_id": item.capture_id, "role": item.role}
               for item in captures if item.number not in available}
    reports, overlap = {}, {}
    with ExitStack() as stack:
        counters = {name: stack.enter_context(ExactGroupCounter(scratch, max_chunk_bytes=chunk_bytes))
                    for name in KEYS}
        for index, capture in enumerate(captures):
            path = available.get(capture.number)
            if path is None:
                continue
            if progress is not None:
                progress(f"Auditing {path.name}")
            reports[path.name] = scan_capture(path, pins[capture.number], capture, index, counters)
        for name, counter in counters.items():
            if progress is not None:
                progress(f"Combining {name} groups")
            summary = CohortOverlap(captures)
            counter.finish(on_group=summary.add)
            overlap[name] = summary.report()
    roles, gates = assess_roles(reports)
    return {"features": FEATURES, "captures": reports, "missing_captures": missing, "roles": roles,
            "nominal_coverage_failures": gates, "overlap": overlap,
            "requires_label_authority_and_capture_review": True}


def main():
    try:
        pins = {item.number: json.loads((PINS / f"dataset{item.number}-bounded.json").read_text(
            encoding="utf-8"))["sha256"] for item in CAPTURES}
        result = audit(DATA, PINS, pins, progress=lambda message: print(message, file=sys.stderr, flush=True))
    except (OSError, ValueError, KeyError, csv.Error) as error:
        print(f"IoT-23 CSV audit failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
