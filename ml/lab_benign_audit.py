"""Review bounded lab captures against independently recorded application events."""

import argparse
from collections import Counter, defaultdict
from hashlib import sha256
from pathlib import Path
import re
from statistics import median

from ml.lab_benign import CLIENT, HTTP_PORT, SENSOR, UDP_PORT, plan
from ml.lab_capture import audit
from ml.lab_registry import digest, load_verified, read_object, register, utc_ns, write_new_object
from ml.lab_zeek import CORE_FIELDS, RICH_FIELDS, read_flows


NUMERICAL = ("duration_ns", "orig_pkts", "resp_pkts", "orig_ip_bytes", "resp_ip_bytes",
             "orig_bytes", "resp_bytes", "missed_bytes")
PROBES = ["host", "internet_ipv4", "internet_ipv6", "lan_gateway"]


def evidence_key(transaction):
    return {
        "method": transaction.method,
        "request_bytes": len(transaction.request), "response_bytes": len(transaction.response),
        "request_sha256": sha256(transaction.request).hexdigest(),
        "response_sha256": sha256(transaction.response).hexdigest(),
    }


def indexed_events(entries):
    result = {row["id"]: row for row in entries}
    if len(result) != len(entries):
        raise ValueError("duplicate transaction evidence")
    return result


def prove_isolation(evidence, role, address):
    record = evidence["isolation"]
    if (record["role"] != role or record["local"] != address or record["no_route"] != PROBES
            or record["forwarding"] is not False or record["lab_route"] != "10.75.26.0/24"):
        raise ValueError(f"{role} isolation evidence failed")
    return utc_ns(record["checked_utc"])


def review(spec, groups, client, sensor, flows):
    """Match completed, expected application events to whole bidirectional flows."""
    capture_id = spec["capture_id"]
    if client["capture_id"] != capture_id or sensor["capture_id"] != capture_id or sensor["scenario"] != spec:
        raise ValueError("application logs describe a different scenario")
    client_checked = prove_isolation(client, "client", CLIENT)
    sensor_checked = prove_isolation(sensor, "sensor", SENSOR)
    start, end = utc_ns(sensor["start"]), utc_ns(sensor["end"])
    if not sensor_checked < start < end:
        raise ValueError("sensor isolation must precede capture")
    client_events, sensor_events = indexed_events(client["events"]), indexed_events(sensor["events"])
    expected_ids = {t.id for group in groups for t in group}
    if set(client_events) != expected_ids or set(sensor_events) != expected_ids:
        raise ValueError("missing or unexpected application transactions")
    by_tuple = {(flow.features["proto"], *flow.endpoints): flow for flow in flows}
    if len(by_tuple) != len(flows) or len(flows) != len(groups):
        raise ValueError("expected one distinct Zeek flow per planned connection")

    for group in groups:
        port = UDP_PORT if group[0].method == "udp" else HTTP_PORT
        protocol = "udp" if port == UDP_PORT else "tcp"
        endpoints = client_events[group[0].id]["endpoints"]
        if (len(endpoints) != 4 or endpoints[0] != CLIENT or endpoints[2:] != [SENSOR, port]
                or type(endpoints[1]) is not int or not 1 <= endpoints[1] <= 65_535):
            raise ValueError("unexpected connection metadata in application evidence")
        flow = by_tuple.pop((protocol, *endpoints), None)
        if flow is None or not flow.core_eligible:
            raise ValueError("missing or incomplete Zeek connection")
        ts, duration = flow.timestamp_ns, flow.features["duration_ns"]
        if ts is None or duration is None or not start <= ts <= ts + duration < end:
            raise ValueError("Zeek connection bounds are unverified")
        if (flow.features["orig_pkts"] <= 0 or flow.features["resp_pkts"] <= 0
                or flow.features["missed_bytes"] != 0):
            raise ValueError("expected a complete bidirectional Zeek connection")
        for transaction in group:
            left, right = client_events[transaction.id], sensor_events[transaction.id]
            for event in (left, right):
                if event["endpoints"] != endpoints or any(
                    event[key] != value for key, value in evidence_key(transaction).items()
                ):
                    raise ValueError("application evidence disagrees with the planned transaction")
            if not client_checked <= utc_ns(left["start"]) <= utc_ns(left["end"]):
                raise ValueError("client transaction timestamps are inconsistent")
            # The service records completion after writing its reply.
            limit = min(end, ts + duration + 250_000_000)
            if not ts <= utc_ns(right["start"]) <= utc_ns(right["end"]) <= limit:
                raise ValueError("service event does not align with the Zeek connection")

    if by_tuple:
        raise ValueError("unattributed network connections remain")


def summarize(flows):
    issues = Counter((field, status) for flow in flows for field, status in flow.issues.items())
    source_fields = {field: field for field in ("ts", *RICH_FIELDS)}
    source_fields["duration_ns"] = "duration"
    counts = {}
    for field in NUMERICAL:
        values = [f.features[field] for f in flows if f.features[field] is not None]
        if values:
            counts[field] = {"sum": sum(values), "min": min(values), "max": max(values),
                             "median": median(values), "count": len(values)}
    return {
        "flows": len(flows),
        "protocol": Counter(f.features["proto"] or "unavailable" for f in flows),
        "service": Counter(f.features["service"] or "unavailable" for f in flows),
        "connection_state": Counter(f.features["conn_state"] or "unavailable" for f in flows),
        "features": {field: {status: issues[(source, status)] for status in ("missing", "invalid")}
                     for field, source in source_fields.items()},
        "numerical": counts,
    }


def capture_stats(path):
    data = path.read_text(encoding="utf-8")
    patterns = {"captured": r"(\d+) packets? captured", "filter": r"(\d+) packets? received by filter",
                "dropped": r"(\d+) packets? dropped by kernel"}
    matches = {key: re.findall(pattern, data) for key, pattern in patterns.items()}
    if any(len(values) != 1 for values in matches.values()):
        raise ValueError("missing or ambiguous tcpdump packet statistics")
    return {key: int(values[0]) for key, values in matches.items()}


def register_review(root, capture_id, spec, sensor, evidence_files, problems, authorization):
    review_file = f"evidence/{capture_id}-review.json"
    report = {"capture_id": capture_id, "problems": problems,
              "source_evidence_sha256": {name: digest(root / name) for name in evidence_files}}
    report_path = root / review_file
    if not report_path.exists():
        write_new_object(report_path, report)
    elif read_object(report_path) != report:
        raise ValueError(f"review evidence changed for {capture_id}")
    start, end = sensor["start"], sensor["end"]
    manifest = {
        "version": 1, "capture_id": capture_id, "session_id": spec["session_id"],
        "source": "authorized_lab", "role": "fit", "scenario": "g27-benign-services",
        "environment_id": "sentinelai-private-g26", "device_ids": ["g26-client", "g26-sensor"],
        "observation_point": "sensor-lab0", "collection_profile": "g27-tcpdump-zeek",
        "pcap": f"raw/{capture_id}.pcap", "conn_log": f"zeek/{capture_id}/conn.log",
        "zeek_receipt": f"zeek/{capture_id}/run.json", "authorization": authorization,
        "start": start, "end": end, "windows": [] if problems else [{
            "start": start, "end": end, "label": "benign", "evidence": review_file,
            "scope": "all_observed_flows", "evidence_kind": "scenario_event_log",
            "author": "g27-client-and-service", "reviewer": "g27-artifact-review",
        }],
    }
    if (root / f"registry/{capture_id}.json").is_file():
        registered, _ = load_verified(root, capture_id)
        if registered["capture"] != manifest:
            raise ValueError(f"review differs from the existing registration for {capture_id}")
    else:
        register(root, manifest)


def evaluate(root, sessions, authorization):
    reports, blockers, registered = {}, [], []
    vectors, all_flows = defaultdict(set), []
    for capture_id, (spec, groups) in sessions.items():
        base = f"evidence/{capture_id}"
        evidence = [f"{base}-client.json", f"{base}-sensor.json", f"{base}-tcpdump.txt"]
        try:
            client, sensor = (read_object(root / name) for name in evidence[:2])
            log = root / f"zeek/{capture_id}"
            receipt = read_object(log / "run.json")
            flows = list(read_flows(log / "conn.log", receipt["conn_sha256"]))
            stats = capture_stats(root / evidence[2])
        except (OSError, KeyError, TypeError, ValueError) as error:
            blockers.append(f"{capture_id} could not read evidence or parsed flows: {error}")
            continue
        quality = summarize(flows)
        problems = []
        recorded = sum(quality["numerical"].get(field, {}).get("sum", 0) for field in ("orig_pkts", "resp_pkts"))
        if stats["dropped"] or not 0 < stats["captured"] < 10_000 or recorded != stats["captured"]:
            problems.append("tcpdump and Zeek packet coverage check failed")
        try:
            review(spec, groups, client, sensor, flows)
        except (KeyError, TypeError, ValueError) as error:
            problems.append(str(error))
        if any(quality["features"][field]["invalid"] for field in quality["features"]):
            problems.append("invalid values in normalized features")
        register_review(root, capture_id, spec, sensor, evidence, problems, authorization)
        registered.append(capture_id)
        blockers.extend(f"{capture_id} {problem}" for problem in problems)
        reports[capture_id] = {**quality, "tcpdump": stats, "scenario": spec,
                               "application_transactions": len(client["events"]), "problems": problems}
        all_flows.extend(flows)
        for flow in flows:
            if flow.core_eligible:
                vectors[flow.vector(CORE_FIELDS)].add(capture_id)

    overlap = audit(root, registered) if registered else None
    if overlap:
        for blocker in overlap["blockers"]:
            if not blocker.startswith(("fit lacks", "calibration lacks", "comparison lacks", "validation ")):
                blockers.append(blocker)
        for capture_id in registered:
            reports[capture_id]["labels"] = overlap["captures"][capture_id]["labeled"]
            if reports[capture_id]["labels"].get("unknown") or reports[capture_id]["labels"].get("attack"):
                blockers.append(f"{capture_id} has unreviewed or unexpected labels")
        if overlap["overlap"]["zeek_core"]["global_counts"].get("label_conflict_keys", 0):
            blockers.append("known binary labels conflict on identical core vectors")
    return {
        "passes_collection_gates": not blockers and bool(registered), "blockers": blockers,
        "captures": reports, "aggregate": summarize(all_flows), "registry_audit": overlap,
        "shared_core_keys_across_sessions": sum(len(ids) > 1 for ids in vectors.values()),
        "distinct_environments": 1 if registered else 0, "distinct_devices": 2 if registered else 0,
        "device_independence": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("report", type=Path)
    parser.add_argument("plans", nargs="+", type=Path)
    parser.add_argument("--authorization", default="evidence/g27-authorization.json")
    args = parser.parse_args()
    try:
        sessions = plan({"version": 1, "sessions": [s for p in args.plans for s in read_object(p)["sessions"]]})
        result = evaluate(args.root, sessions, args.authorization)
        write_new_object(args.report, result)
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(2, f"Lab audit stopped: {error}\n")
    return 0 if result["passes_collection_gates"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
