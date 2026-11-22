"""Project and audit seven versioned predictors from offline Zeek observations."""

import argparse
from collections import Counter
import json
from pathlib import Path

from ml.lab_capture import capture_rows, same_lineage
from ml.lab_registry import load_verified_capture
from ml.lab_zeek import CONNECTION_STATES, CORE_FIELDS


CONTRACT = "zeek-flow-v1"
ZEEK_VERSION = "8.0.11"
PROTOCOLS = frozenset(("tcp", "udp"))
FIELDS = (*CORE_FIELDS, "duration_ns", "conn_state")
OPTIONAL_FIELDS = frozenset(("duration_ns", "conn_state"))
MAX_SIGNED_COUNT = 2**63 - 1
MAX_CAPTURES = 16
MAX_RECORDS = 10_000
MAX_ARTIFACT_BYTES = 64 * 1024**2
LABELS = ("benign", "attack", "unknown")


def field_status(name, value, issues):
    source_name = "duration" if name == "duration_ns" else name
    if issues.get(source_name) == "invalid":
        return "invalid"
    if value is None:
        return "missing"
    if name in ("proto", "conn_state"):
        vocabulary = PROTOCOLS if name == "proto" else CONNECTION_STATES
        return "present" if isinstance(value, str) and value in vocabulary else "unsupported"
    return "present" if type(value) is int and 0 <= value <= MAX_SIGNED_COUNT else "invalid"


def inspect_predictors(features, *, issues=None):
    """Return a fixed-order predictor mapping when valid, alongside field coverage.

    Inputs are normalized by the existing Zeek parser or loaded from the
    equivalent offline-ingestion fields. Null optional values stay null.
    """
    issues = {} if issues is None else issues
    values = {name: features.get(name) for name in FIELDS}
    status = {name: field_status(name, value, issues) for name, value in values.items()}
    eligible = all(state == "present" or (name in OPTIONAL_FIELDS and state == "missing")
                   for name, state in status.items())
    return values if eligible else None, status


def audit_rows(rows):
    coverage = {name: Counter() for name in FIELDS}
    labels, eligible_labels, vectors, protocols = (Counter() for _ in range(4))
    by_label = {"benign": set(), "attack": set()}
    direction_mismatches = 0
    for index, (flow, (label, _, _)) in enumerate(rows, 1):
        if index > MAX_RECORDS:
            raise ValueError(f"capture exceeds the limit of {MAX_RECORDS:,} flow records")
        labels[label] += 1
        vector, status = inspect_predictors(flow.features, issues=flow.issues)
        for name, state in status.items():
            coverage[name][state] += 1
        if vector is None:
            continue
        eligible_labels[label] += 1
        protocols[vector["proto"]] += 1
        key = tuple(vector.values())
        vectors[key] += 1
        if label in by_label:
            by_label[label].add(key)
        for direction in ("orig", "resp"):
            direction_mismatches += (vector[f"{direction}_pkts"] == 0) != (vector[f"{direction}_ip_bytes"] == 0)
    if not labels:
        raise ValueError("capture has no flow records")
    return {
        "rows": labels.total(), "eligible_rows": vectors.total(),
        "ground_truth": {name: labels[name] for name in LABELS},
        "eligible_by_ground_truth": {name: eligible_labels[name] for name in LABELS},
        "fields": coverage, "eligible_protocols": protocols,
        "zero_packet_byte_direction_mismatches": direction_mismatches,
    }, vectors, by_label


def vector_counts(vectors):
    repeated = [count for count in vectors.values() if count > 1]
    return {"unique_vectors": len(vectors), "repeated_vectors": len(repeated),
            "rows_on_repeated_vectors": sum(repeated), "extra_rows": sum(repeated) - len(repeated)}


def audit(captures):
    """Audit a bounded real cohort without changing records or choosing training roles."""
    if not 1 <= len(captures) <= MAX_CAPTURES:
        raise ValueError(f"provide between 1 and {MAX_CAPTURES} captures")
    ids = [capture_id for _, capture_id in captures]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate capture ID")

    seen_pcaps, seen_logs = set(), set()
    reports, manifests = [], []
    all_vectors, capture_support = Counter(), Counter()
    reviewed = {"benign": set(), "attack": set()}
    for root, capture_id in sorted(captures, key=lambda item: item[1]):
        manifest, windows, receipt = load_verified_capture(root, capture_id, max_artifact_bytes=MAX_ARTIFACT_BYTES)
        spec, hashes = manifest["capture"], manifest["sha256"]
        if spec["source"] == "synthetic":
            raise ValueError("synthetic captures are excluded from the real contract audit")
        if hashes["pcap"] in seen_pcaps or hashes["conn_log"] in seen_logs:
            raise ValueError("duplicate PCAP or Zeek log")
        seen_pcaps.add(hashes["pcap"])
        seen_logs.add(hashes["conn_log"])
        if receipt["zeek_version"].split()[-1:] != [ZEEK_VERSION]:
            raise ValueError(f"expected a Zeek {ZEEK_VERSION} receipt for the contract audit")
        manifests.append(manifest)
        rows = capture_rows(root, manifest, windows, max_log_bytes=MAX_ARTIFACT_BYTES)
        report, vectors, by_label = audit_rows(rows)
        reports.append({"capture_id": capture_id, **report, **vector_counts(vectors)})
        all_vectors.update(vectors)
        capture_support.update(vectors.keys())
        for label, keys in by_label.items():
            reviewed[label].update(keys)

    specs = [manifest["capture"] for manifest in manifests]
    conflicts = reviewed["benign"] & reviewed["attack"]
    return {
        "contract": CONTRACT, "zeek_version": ZEEK_VERSION, "predictor_order": FIELDS,
        "captures": reports,
        "lineage": {
            "captures": len(specs), "sessions": len({spec["session_id"] for spec in specs}),
            "devices": len({device for spec in specs for device in spec["device_ids"]}),
            "environments": len({spec["environment_id"] for spec in specs}),
            "observation_points": len({(spec["environment_id"], spec["observation_point"]) for spec in specs}),
            "warnings": same_lineage(manifests),
        },
        "overall": {
            "rows": sum(report["rows"] for report in reports), "eligible_rows": all_vectors.total(),
            "ground_truth": {name: sum(report["ground_truth"][name] for report in reports) for name in LABELS},
            "eligible_by_ground_truth": {name: sum(report["eligible_by_ground_truth"][name] for report in reports)
                                         for name in LABELS},
            "fields": {name: sum((report["fields"][name] for report in reports), Counter()) for name in FIELDS},
            "eligible_protocols": sum((report["eligible_protocols"] for report in reports), Counter()),
            "zero_packet_byte_direction_mismatches": sum(report["zero_packet_byte_direction_mismatches"] for report in reports),
            "vectors_shared_across_captures": sum(count > 1 for count in capture_support.values()),
            "reviewed_label_conflicting_vectors": len(conflicts),
            **vector_counts(all_vectors),
        },
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", action="append", nargs=2, required=True,
                        metavar=("REGISTRY_ROOT", "CAPTURE_ID"), help="select a registered capture, repeat for each capture")
    args = parser.parse_args(argv)
    try:
        report = audit([(Path(root), capture_id) for root, capture_id in args.capture])
    except (OSError, TypeError, ValueError, KeyError) as error:
        parser.exit(1, f"Feature audit stopped: {error}\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
