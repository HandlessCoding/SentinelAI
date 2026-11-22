"""Import one locally registered Zeek capture into PostgreSQL without network collection."""

import argparse
from hashlib import sha256
from ipaddress import ip_address
import json
from pathlib import Path
import re

from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from backend.database import DatabaseConfigurationError, get_engine
from backend.models import ZeekCapture, ZeekFlow
from backend.zeek_rules import PROTOCOLS, STATE_PATTERN, rule_for_flow
from ml.lab_capture import capture_rows
from ml.lab_registry import DEFAULT_ROOT, load_verified_capture
from ml.lab_zeek import COUNTERS


MAX_ARTIFACT_BYTES = 64 * 1024**2
MAX_ROWS = 10_000
SIGNED_BIGINT_MAX = 2**63 - 1


def read_endpoint(host, port):
    address = None
    if host not in (None, "-"):
        if not isinstance(host, str) or "%" in host:
            raise ValueError("expected an IP address")
        try:
            address = str(ip_address(host))
        except ValueError:
            raise ValueError("expected an IP address") from None
    if port in (None, "-"):
        port = None
    elif type(port) is not int or not 0 <= port <= 65535:
        raise ValueError("expected a port between 0 and 65535")
    return address, port


def flow_values(capture_id, index, flow, label):
    fields = flow.features
    ground_truth, category, reason = label
    if flow.timestamp_ns is None or flow.timestamp_ns > SIGNED_BIGINT_MAX or reason == "outside_capture":
        raise ValueError("invalid timestamp or timestamp outside the capture")
    if fields["proto"] not in PROTOCOLS or "invalid" in flow.issues.values():
        raise ValueError("invalid Zeek feature or unrecognized protocol")
    state = fields["conn_state"]
    if state is not None and not re.fullmatch(STATE_PATTERN, state):
        raise ValueError("invalid connection state")
    if any(fields[name] is not None and not fields[name].isprintable() for name in ("service", "history")):
        raise ValueError("invalid service or history text")
    amounts = {name: fields[name] for name in (*COUNTERS, "duration_ns")}
    if any(value is not None and value > SIGNED_BIGINT_MAX for value in amounts.values()):
        raise ValueError("counter or duration exceeds the supported range")
    orig, orig_port = read_endpoint(*flow.endpoints[:2])
    resp, resp_port = read_endpoint(*flow.endpoints[2:])
    return dict(
        capture_id=capture_id, source_row=index, timestamp_ns=flow.timestamp_ns,
        proto=fields["proto"], conn_state=state, service=fields["service"], history=fields["history"],
        orig_host=orig, orig_port=orig_port, resp_host=resp, resp_port=resp_port,
        ground_truth=ground_truth, label_category=category, label_reason=reason,
        rule_code=rule_for_flow(fields["proto"], state), **amounts,
    )


def import_capture(db, root, capture_id):
    """Validate a bounded capture and store it atomically, including concurrent retries."""
    manifest, windows, receipt = load_verified_capture(root, capture_id, max_artifact_bytes=MAX_ARTIFACT_BYTES)
    spec, hashes = manifest["capture"], manifest["sha256"]
    if spec["source"] == "synthetic":
        raise ValueError("synthetic captures cannot be imported as recorded traffic")

    version = receipt["zeek_version"]
    if not 1 <= len(version) <= 128 or not version.isprintable():
        raise ValueError("invalid Zeek version in the registered receipt")
    checksum = sha256(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    rows = []
    for index, (flow, label) in enumerate(capture_rows(root, manifest, windows, max_log_bytes=MAX_ARTIFACT_BYTES), 1):
        if index > MAX_ROWS:
            raise ValueError(f"capture exceeds the import limit of {MAX_ROWS:,} flows")
        try:
            rows.append(flow_values(capture_id, index, flow, label))
        except ValueError as error:
            raise ValueError(f"Zeek row {index}: {error}") from None
    if not rows:
        raise ValueError("capture contains no Zeek flows")

    with db.begin():
        created = db.scalar(
            insert(ZeekCapture)
            .values(
                capture_id=capture_id, session_id=spec["session_id"], environment_id=spec["environment_id"],
                observation_point=spec["observation_point"], source=spec["source"], zeek_version=version,
                pcap_sha256=hashes["pcap"], conn_sha256=hashes["conn_log"], manifest_sha256=checksum,
                flow_count=len(rows),
            )
            .on_conflict_do_nothing()
            .returning(ZeekCapture.capture_id)
        )
        if created is None:
            previous = db.get(ZeekCapture, capture_id)
            if previous is None or previous.manifest_sha256 != checksum:
                raise ValueError("capture identity or source bytes were already imported with different provenance")
        else:
            db.execute(insert(ZeekFlow), rows)
    return {"capture_id": capture_id, "flow_count": len(rows), "replayed": created is None}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    parser.add_argument("capture_id", help="capture ID from the local registry")
    args = parser.parse_args(argv)
    try:
        with Session(get_engine()) as db:
            result = import_capture(db, args.root, args.capture_id)
    except (SQLAlchemyError, DatabaseConfigurationError):
        parser.exit(1, "Import stopped. Check local PostgreSQL and apply the database migrations.\n")
    except (ValueError, KeyError, TypeError):
        parser.exit(1, "Import stopped. Check the registered capture, limits, and provenance.\n")
    except OSError:
        parser.exit(1, "Import stopped. Check that the registered local files are available.\n")
    print(json.dumps(result))


if __name__ == "__main__":
    main()
