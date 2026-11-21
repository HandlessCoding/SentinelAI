"""Capture registration, read-only extraction, and cohort preflight commands."""

import argparse
from collections import Counter
from contextlib import ExitStack
from itertools import combinations
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

from ml.audit_cic_release import tuple_key
from ml.audit_iot23_captures import MIN_CATEGORY_ROWS, MIN_CLASS_ROWS, PROTOCOLS, ROLES
from ml.audit_iot23_kaggle import CohortOverlap
from ml.lab_registry import DEFAULT_ROOT, lab_path, load_verified, read_object, register, time_bounds
from ml.lab_zeek import CORE_FIELDS, RICH_FIELDS, WindowLabels, count, read_flows, run_zeek
from ml.level2_audit_storage import ExactGroupCounter


LABELS = {"benign": 0, "attack": 1, "unknown": None}


def capture_rows(root, manifest, windows):
    spec = manifest["capture"]
    labeler = WindowLabels(windows, time_bounds(spec))
    conn = lab_path(root, spec["conn_log"])
    for flow in read_flows(conn, manifest["sha256"]["conn_log"]):
        yield flow, labeler.classify(flow)


def same_lineage(manifests):
    """Find copied captures, cross-role group reuse, and same-sensor time overlap."""
    violations = set()
    for first, second in combinations(manifests, 2):
        left, right = first["capture"], second["capture"]
        pair = f"{left['capture_id']} / {right['capture_id']}"
        for artifact in ("pcap", "conn_log"):
            if first["sha256"][artifact] == second["sha256"][artifact]:
                violations.add(f"same {artifact} bytes in {pair}")
        if left["role"] != right["role"]:
            if left["session_id"] == right["session_id"]:
                violations.add(f"cross-role session reuse in {pair}")
            if set(left["device_ids"]).intersection(right["device_ids"]):
                violations.add(f"cross-role device reuse in {pair}")
        if (left["environment_id"], left["observation_point"]) == (
            right["environment_id"], right["observation_point"]
        ):
            left_start, left_end = time_bounds(left)
            right_start, right_end = time_bounds(right)
            if max(left_start, right_start) < min(left_end, right_end):
                violations.add(f"overlapping clock windows at the same observation point in {pair}")
    return sorted(violations)


def role_coverage(captures):
    roles = {role: {"labeled": Counter(), "eligible": Counter(), "attack_categories": Counter(),
                    "eligible_categories": Counter(), "attack_sessions": set()} for role in ROLES}
    for report in captures.values():
        spec = report["capture"]
        if spec["source"] == "synthetic":
            continue
        entry = roles[spec["role"]]
        for key in ("labeled", "eligible", "attack_categories", "eligible_categories"):
            entry[key].update(report[key])
        if report["eligible"]["attack"]:
            entry["attack_sessions"].add(spec["session_id"])
    failures = []
    for role, report in roles.items():
        for label in ("benign", "attack"):
            available = report["eligible"][label]
            if available < MIN_CLASS_ROWS or 2 * available < report["labeled"][label]:
                failures.append(f"{role} lacks eligible {label} support")
        for category, observed in report["attack_categories"].items():
            if observed >= MIN_CATEGORY_ROWS and 2 * report["eligible_categories"][category] < observed:
                failures.append(f"{role} lacks eligible support for category {category}")
        report["attack_sessions"] = sorted(report["attack_sessions"])
    if len(roles["validation"]["attack_sessions"]) < 2:
        failures.append("validation needs at least two distinct attack sessions")
    return roles, failures


def count_overlap(root, inputs, reports):
    specs = [SimpleNamespace(capture_id=m["capture"]["capture_id"], role=m["capture"]["role"])
             for m, _ in inputs]
    families = ("zeek_core", "zeek_rich_diagnostic", "tuple", "tuple_at_start")
    summaries = {name: CohortOverlap(specs) for name in families}
    # Build all key families while streaming each log once with bounded scratch storage.
    with ExitStack() as stack:
        counters = {name: stack.enter_context(ExactGroupCounter(root, max_chunk_bytes=16 * 1024**2))
                    for name in families}
        for index, (manifest, windows) in enumerate(inputs):
            spec = manifest["capture"]
            labeled, eligible, reasons, categories, kept, issues = (Counter() for _ in range(6))
            protocols = {}
            for flow, (label, category, reason) in capture_rows(root, manifest, windows):
                labeled[label] += 1
                reasons[reason] += 1
                issues.update(f"{field}:{status}" for field, status in flow.issues.items())
                protocols.setdefault(label, Counter())[flow.features["proto"] or "unavailable"] += 1
                if category is not None:
                    categories[category] += 1
                if flow.core_eligible:
                    eligible[label] += 1
                    if category is not None:
                        kept[category] += 1
                suffix = bytes((index,))
                if flow.core_eligible:
                    counters["zeek_core"].add(flow.vector(CORE_FIELDS) + suffix, LABELS[label])
                    counters["zeek_rich_diagnostic"].add(flow.vector(RICH_FIELDS) + suffix, LABELS[label])
                if endpoint := five_tuple(flow):
                    counters["tuple"].add(endpoint + suffix, LABELS[label])
                    if flow.timestamp_ns is not None:
                        start = flow.timestamp_ns.to_bytes(8, "big")
                        counters["tuple_at_start"].add(endpoint + start + suffix, LABELS[label])
            reports[spec["capture_id"]] = {
                "capture": {key: spec[key] for key in ("capture_id", "environment_id", "device_ids",
                                                       "role", "source", "session_id", "collection_profile")},
                "labeled": labeled, "eligible": eligible, "label_reasons": reasons, "feature_issues": issues,
                "protocols": protocols, "attack_categories": categories, "eligible_categories": kept,
            }
        for name, counter in counters.items():
            counter.finish(on_group=summaries[name].add)
    return {name: summary.report() for name, summary in summaries.items()}


def five_tuple(flow):
    protocol = PROTOCOLS.get(flow.features["proto"])
    if protocol is None:
        return None
    origin, origin_port, response, response_port = flow.endpoints
    if not isinstance(origin, str) or not isinstance(response, str):
        return None
    try:
        return tuple_key(origin, count(origin_port), response, count(response_port), protocol)
    except (ValueError, OverflowError):
        return None


def audit(root, ids):
    if not ids or len(ids) > 256 or len(ids) != len(set(ids)):
        raise ValueError("provide between 1 and 256 unique capture IDs")
    inputs = [load_verified(root, capture_id) for capture_id in ids]
    manifests = [manifest for manifest, _ in inputs]
    reports = {}
    overlap = count_overlap(root, inputs, reports)
    roles, failures = role_coverage(reports)
    failures += same_lineage(manifests)
    if len({manifest["capture"]["collection_profile"] for manifest in manifests}) != 1:
        failures.append("collection profiles differ")
    versions = {read_object(lab_path(root, spec["zeek_receipt"]))["zeek_version"]
                for spec in (manifest["capture"] for manifest in manifests) if "zeek_receipt" in spec}
    if len(versions) > 1:
        failures.append("Zeek versions differ")
    if any(m["capture"]["source"] == "synthetic" for m in manifests):
        failures.append("synthetic fixtures must stay outside the real evaluation cohort")
    if any(overlap["tuple_at_start"]["shared_between_roles"].values()):
        failures.append("cross-role tuple and start matches need provenance review")
    return {"captures": reports, "roles": roles, "overlap": overlap, "blockers": failures,
            "passes_automated_gates": not failures, "independent_review_required": True}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=DEFAULT_ROOT, type=Path)
    sub = parser.add_subparsers(dest="action", required=True)
    zeek = sub.add_parser("zeek", help="read a local PCAP with the pinned Zeek settings")
    zeek.add_argument("pcap", help="PCAP path relative to the lab root")
    zeek.add_argument("run_id")
    zeek.add_argument("--binary", default="zeek")
    sub.add_parser("register", help="hash files and seal a capture").add_argument("draft")
    sub.add_parser("records", help="stream normalized JSON records").add_argument("capture_id")
    sub.add_parser("audit", help="report coverage and overlap").add_argument("capture_ids", nargs="+")
    args = parser.parse_args(argv)
    try:
        if args.action == "zeek":
            print(run_zeek(args.root, args.pcap, args.run_id, args.binary))
        elif args.action == "register":
            print(register(args.root, read_object(lab_path(args.root, args.draft))))
        elif args.action == "records":
            manifest, windows = load_verified(args.root, args.capture_id)
            for flow, (label, category, reason) in capture_rows(args.root, manifest, windows):
                print(json.dumps({
                    "capture_id": args.capture_id, "source": manifest["capture"]["source"],
                    "timestamp_ns": flow.timestamp_ns, "label": label, "category": category,
                    "label_reason": reason, "features": flow.features, "issues": flow.issues,
                    "core_eligible": flow.core_eligible,
                }))
        else:
            report = audit(args.root, args.capture_ids)
            print(json.dumps(report, indent=2, sort_keys=True))
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(f"Capture workflow stopped: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
