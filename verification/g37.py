"""Independent evidence helpers for G37 connected sensor verification."""

import json
from dataclasses import dataclass
from decimal import Decimal
from hashlib import sha256
from pathlib import Path


@dataclass(frozen=True)
class FlowIdentity:
    uid: str
    timestamp_ns: int
    stream_key: str


def load_manifest(root: Path) -> dict:
    manifest = json.loads((root / "examples/g37_run_manifest.json").read_bytes())
    if manifest["version"] != 1:
        raise ValueError("Unsupported G37 manifest version")
    fixture = (root / "examples/lab_benign_pilot.json").read_bytes().replace(b"\r\n", b"\n")
    if sha256(fixture).hexdigest() != manifest["fixture"]["sha256_lf"]:
        raise ValueError("G37 fixture digest differs from the run manifest")
    return manifest


def flow_identity(native_line: bytes) -> FlowIdentity:
    """Derive a connected sensor key without calling the worker or its Zeek parser."""
    if len(native_line) > 64 * 1024:
        raise ValueError("Zeek line exceeds the connected sensor limit")
    record = json.loads(native_line, parse_float=Decimal)
    if not isinstance(record, dict):
        raise ValueError("Expected a native Zeek object")
    uid, timestamp = record.get("uid"), record.get("ts")
    if not isinstance(uid, str) or not 1 <= len(uid) <= 128 or not uid.isascii() or not uid.isalnum():
        raise ValueError("Expected a Zeek UID")
    if type(timestamp) not in {int, Decimal} or not 0 <= timestamp <= 9_999_999_999:
        raise ValueError("Expected a supported numeric first-packet timestamp")
    if timestamp and timestamp < Decimal("0.000000001"):
        raise ValueError("First-packet timestamp exceeds nanosecond precision")
    numerator, denominator = timestamp.as_integer_ratio()
    nanoseconds, remainder = divmod(numerator * 1_000_000_000, denominator)
    if remainder:
        raise ValueError("First-packet timestamp exceeds nanosecond precision")
    if nanoseconds > 2**63 - 1:
        raise ValueError("First-packet timestamp exceeds PostgreSQL bigint range")
    # The validated UID needs no JSON escaping. Source scoping is a separate database column.
    key = sha256(f'["{uid}",{nanoseconds}]'.encode("ascii")).hexdigest()
    return FlowIdentity(uid, nanoseconds, key)


def persistence_upper_bound_ns(
    last_incomplete_start: int, first_complete_end: int, committed_read_end: int
) -> int:
    """Bound complete-line availability to visibility in an independent committed read."""
    if not 0 <= last_incomplete_start <= first_complete_end <= committed_read_end:
        raise ValueError("Persistence observations must be nonnegative and ordered")
    return committed_read_end - last_incomplete_start
