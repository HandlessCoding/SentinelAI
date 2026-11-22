"""Project Zeek TCP history markers and audit their coverage in a verified capture."""

import argparse
from collections import Counter
import json
from pathlib import Path

from ml.lab_capture import capture_rows
from ml.lab_registry import lab_path, load_verified, read_object
from ml.zeek_flow_v1 import FIELDS, MAX_ARTIFACT_BYTES, MAX_RECORDS, ZEEK_VERSION, inspect_predictors


CONTRACT = "zeek-flow-history-v1"
HISTORY_FIELDS = ("orig_data_seen", "resp_data_seen", "orig_reset_seen", "resp_reset_seen")
HISTORY_MARKERS = "DdRr"
HISTORY_ALPHABET = frozenset("SHADFRCGTWIQXshadfrcgtwiqx^")


def inspect_history_predictors(features, *, issues=None):
    """Append nullable marker presence flags to an eligible v1 record."""
    issues = {} if issues is None else issues
    core, _ = inspect_predictors(features, issues=issues)
    if core is None:
        return None, "ineligible_base"

    history = features.get("history")
    if core["proto"] != "tcp":
        status = "not_applicable"
    elif issues.get("history") == "invalid":
        status = "invalid"
    elif history is None or history == "-":
        status = "missing"
    elif not isinstance(history, str) or not 1 <= len(history) <= 1024:
        status = "invalid"
    elif not HISTORY_ALPHABET.issuperset(history):
        status = "unsupported"
    else:
        flags = dict(zip(HISTORY_FIELDS, (marker in history for marker in HISTORY_MARKERS), strict=True))
        return {**core, **flags}, "present"
    return {**core, **dict.fromkeys(HISTORY_FIELDS)}, status


def audit_capture(root, capture_id):
    manifest, windows = load_verified(root, capture_id, max_artifact_bytes=MAX_ARTIFACT_BYTES)
    spec = manifest["capture"]
    if spec["source"] == "synthetic":
        raise ValueError("history coverage requires a real capture")
    receipt = read_object(lab_path(root, spec["zeek_receipt"]))
    if receipt["zeek_version"].split()[-1:] != [ZEEK_VERSION]:
        raise ValueError(f"expected a Zeek {ZEEK_VERSION} receipt")

    coverage, marker_counts = Counter(), Counter(dict.fromkeys(HISTORY_FIELDS, 0))
    for index, (flow, _) in enumerate(
        capture_rows(root, manifest, windows, max_log_bytes=MAX_ARTIFACT_BYTES), 1
    ):
        if index > MAX_RECORDS:
            raise ValueError(f"capture exceeds the limit of {MAX_RECORDS:,} flow records")
        vector, status = inspect_history_predictors(flow.features, issues=flow.issues)
        coverage[status] += 1
        if status == "present":
            marker_counts.update({name: vector[name] for name in HISTORY_FIELDS})
    if not coverage:
        raise ValueError("capture has no flow records")
    return {
        "capture_id": capture_id,
        "contract": CONTRACT,
        "zeek_version": ZEEK_VERSION,
        "predictor_order": (*FIELDS, *HISTORY_FIELDS),
        "history_coverage": coverage,
        "marker_rows": marker_counts,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("registry_root", type=Path)
    parser.add_argument("capture_id")
    args = parser.parse_args(argv)
    try:
        report = audit_capture(args.registry_root, args.capture_id)
    except (OSError, TypeError, ValueError, KeyError) as error:
        parser.exit(1, f"History audit stopped: {error}\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
