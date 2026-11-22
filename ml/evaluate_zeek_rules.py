"""Audit versioned TCP rule findings against labels in local capture registries."""

import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path

from backend.zeek_rules import RULES_BY_STATE, rule_for_flow
from ml.lab_capture import capture_rows, same_lineage
from ml.lab_registry import load_verified


MAX_CAPTURES = 64
MAX_ROWS = 10_000
MAX_ARTIFACT_BYTES = 64 * 1024**2
TCP_STATES = frozenset((
    "S0", "S1", "SF", "REJ", "S2", "S3", "RSTO", "RSTR", "RSTOS0", "RSTRH", "SH", "SHR", "OTH",
))


def count_rows(source, rows):
    """Partition coverage first, then score only supported, reviewed real rows."""
    counts = Counter()
    for index, (flow, (label, _, reason)) in enumerate(rows, 1):
        if index > MAX_ROWS:
            raise ValueError(f"capture exceeds the evaluation limit of {MAX_ROWS:,} rows")
        counts["records"] += 1
        if source == "synthetic":
            counts["synthetic"] += 1
            continue
        if label == "unknown":
            counts["unknown"] += 1
            counts["unknown:" + reason] += 1
            continue

        counts["reviewed_" + label] += 1
        protocol, state = flow.features["proto"], flow.features["conn_state"]
        if protocol != "tcp":
            counts["excluded:outside_tcp_scope"] += 1
        elif state is None and flow.issues.get("conn_state") == "missing":
            counts["excluded:missing_tcp_state"] += 1
        elif state not in TCP_STATES:
            counts["excluded:unrecognized_tcp_state"] += 1
        else:
            code = rule_for_flow(protocol, state)
            if code:
                counts["finding:" + code] += 1
            if label == "attack":
                counts["tp" if code else "fn"] += 1
            else:
                counts["fp" if code else "tn"] += 1
    return counts


def report_counts(counts):
    def by_reason(prefix):
        return {key.removeprefix(prefix): value for key, value in sorted(counts.items()) if key.startswith(prefix)}

    def rate(numerator, denominator):
        return numerator / denominator if denominator else None

    tp, fp, tn, fn = (counts[key] for key in ("tp", "fp", "tn", "fn"))
    excluded = by_reason("excluded:")
    return {
        "coverage": {
            "records": counts["records"], "synthetic": counts["synthetic"], "unknown": counts["unknown"],
            "unknown_reasons": by_reason("unknown:"), "excluded_reviewed": sum(excluded.values()),
            "exclusion_reasons": excluded, "reviewed_benign": counts["reviewed_benign"],
            "reviewed_attack": counts["reviewed_attack"], "eligible_reviewed": tp + fp + tn + fn,
            "eligible_benign": fp + tn, "eligible_attack": tp + fn,
        },
        "confusion": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "metrics": {"precision": rate(tp, tp + fp), "recall": rate(tp, tp + fn),
                    "false_positive_rate": rate(fp, fp + tn)},
        "positive_class_evaluation_available": tp + fn > 0,
        "findings_by_rule": {code: counts["finding:" + code] for code in sorted(RULES_BY_STATE.values())},
    }


def evaluate(captures):
    """Read an explicit cohort of (registry root, capture ID) pairs without writes."""
    if not 1 <= len(captures) <= MAX_CAPTURES:
        raise ValueError(f"provide between 1 and {MAX_CAPTURES} captures")

    manifests, reports = [], []
    seen_ids, seen_pcaps, seen_logs = set(), set(), set()
    aggregate = Counter()
    sessions, devices, environments = defaultdict(Counter), defaultdict(Counter), defaultdict(Counter)
    for root, capture_id in captures:
        if capture_id in seen_ids:
            raise ValueError("duplicate capture ID in evaluation cohort")
        manifest, windows = load_verified(root, capture_id, max_artifact_bytes=MAX_ARTIFACT_BYTES)
        spec, hashes = manifest["capture"], manifest["sha256"]
        if hashes["pcap"] in seen_pcaps or hashes["conn_log"] in seen_logs:
            raise ValueError("duplicate PCAP or Zeek log in evaluation cohort")
        seen_ids.add(capture_id)
        seen_pcaps.add(hashes["pcap"])
        seen_logs.add(hashes["conn_log"])
        manifests.append(manifest)

        rows = capture_rows(root, manifest, windows, max_log_bytes=MAX_ARTIFACT_BYTES)
        counts = count_rows(spec["source"], rows)
        reports.append({"capture_id": capture_id, "session_id": spec["session_id"],
                        "device_ids": spec["device_ids"], "environment_id": spec["environment_id"],
                        "observation_point": spec["observation_point"], "source": spec["source"],
                        "pcap_sha256": hashes["pcap"], "conn_sha256": hashes["conn_log"],
                        **report_counts(counts)})
        aggregate.update(counts)
        environment = spec["environment_id"]
        environments[environment].update(counts)
        sessions[environment, spec["session_id"]].update(counts)
        for device in spec["device_ids"]:
            devices[environment, device].update(counts)

    return {
        "rules_by_tcp_state": dict(RULES_BY_STATE),
        "overall": report_counts(aggregate),
        "captures": sorted(reports, key=lambda report: report["capture_id"]),
        "sessions": [{"environment_id": env, "session_id": session, **report_counts(counts)}
                     for (env, session), counts in sorted(sessions.items())],
        "devices": [{"environment_id": env, "device_id": device, **report_counts(counts)}
                    for (env, device), counts in sorted(devices.items())],
        "environments": [{"environment_id": env, **report_counts(counts)}
                         for env, counts in sorted(environments.items())],
        "lineage_warnings": same_lineage(manifests),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", action="append", nargs=2, required=True,
                        metavar=("REGISTRY_ROOT", "CAPTURE_ID"), help="select a registered capture, repeat for each capture")
    args = parser.parse_args(argv)
    try:
        report = evaluate([(Path(root), capture_id) for root, capture_id in args.capture])
    except (OSError, TypeError, ValueError, KeyError) as error:
        parser.exit(1, f"Rule audit stopped: {error}\n")
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
