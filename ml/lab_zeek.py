"""Run a trusted Zeek binary offline and normalize its JSON connection logs."""

from bisect import bisect_right
from dataclasses import dataclass
from decimal import Decimal, ROUND_CEILING
from hashlib import sha256
import json
from os import fstat
from pathlib import Path
import shutil
import subprocess
from tempfile import TemporaryDirectory

from ml.audit_level2_data import file_identity
from ml.lab_registry import NANOSECOND, ZEEK_SETTINGS, digest, identifier, lab_path, write_new_object


COUNTERS = ("orig_pkts", "resp_pkts", "orig_ip_bytes", "resp_ip_bytes", "orig_bytes", "resp_bytes", "missed_bytes")
TEXT_FIELDS = ("proto", "conn_state", "service", "history")
CORE_FIELDS = ("proto", *COUNTERS[:4])
RICH_FIELDS = (*CORE_FIELDS, "duration_ns", "conn_state", "service", "orig_bytes", "resp_bytes", "missed_bytes", "history")
MAX_LINE = 1024**2
ONE_NANOSECOND_IN_SECONDS = Decimal("0.000000001")


def run_zeek(root, pcap_name, run_id, executable="zeek"):
    capture = lab_path(root, pcap_name)
    binary = shutil.which(executable)
    if binary is None:
        raise FileNotFoundError("Zeek executable is unavailable")
    binary = Path(binary).resolve()
    if binary.suffix.lower() in {".bat", ".cmd"}:
        raise ValueError("select a Zeek executable instead of a shell script wrapper")
    output = lab_path(root, f"zeek/{identifier(run_id)}")
    if output.exists():
        raise FileExistsError("Zeek run ID already exists")
    source_identity = file_identity(capture.stat())
    source_hash = digest(capture, pcap=True)
    if file_identity(capture.stat()) != source_identity:
        raise ValueError("source capture changed before Zeek processing")
    output.parent.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(prefix="offline-", dir=output.parent) as temporary:
        workspace = Path(temporary)
        with (workspace / "diagnostics.txt").open("w+b") as log:
            subprocess.run([str(binary), "--version"], check=True, cwd=workspace,
                           stdout=log, stderr=log, timeout=30)
            log.seek(0)
            version = log.read(4096).decode("utf-8", errors="replace").strip()
            if not version:
                raise ValueError("Zeek did not report a version")
            subprocess.run([str(binary), "-r", str(capture), *ZEEK_SETTINGS], check=True,
                           cwd=workspace, stdout=log, stderr=log, timeout=3600)
        if file_identity(capture.stat()) != source_identity:
            raise ValueError("source capture changed during Zeek processing")
        conn = workspace / "conn.log"
        if not conn.is_file() or conn.stat().st_size == 0:
            raise ValueError("Zeek produced no connection records")
        receipt = {"version": 1, "zeek_version": version, "settings": list(ZEEK_SETTINGS),
                   "pcap_sha256": source_hash, "conn_sha256": digest(conn)}
        complete = workspace / "complete"
        complete.mkdir()
        conn.rename(complete / "conn.log")
        write_new_object(complete / "run.json", receipt)
        complete.rename(output)
    return output


def seconds_ns(value):
    """Convert Zeek seconds to integer nanoseconds without a float round-trip."""
    if type(value) is not int and not isinstance(value, Decimal):
        raise ValueError("expected numeric Zeek seconds")
    if isinstance(value, Decimal) and not value.is_finite():
        raise ValueError("expected finite Zeek seconds")
    if not 0 <= value <= 9_999_999_999:
        raise ValueError("Zeek time is out of range")
    if value == 0:
        return 0
    if isinstance(value, Decimal):
        _, digits, scale = value.as_tuple()
        extra_digits = -scale - 9
        if extra_digits > 0 and (extra_digits >= len(digits) or any(digits[-extra_digits:])):
            raise ValueError("Zeek time exceeds nanosecond precision")
    return int(value * NANOSECOND)


def duration_ns(value):
    """Round Zeek's floating-point intervals up without shortening a label check."""
    if (isinstance(value, Decimal) and value.is_finite()
            and ONE_NANOSECOND_IN_SECONDS <= value <= 9_999_999_999):
        value = value.quantize(ONE_NANOSECOND_IN_SECONDS, rounding=ROUND_CEILING)
    return seconds_ns(value)


def count(value):
    if type(value) is not int or not 0 <= value < 2**64:
        raise ValueError("expected an unsigned Zeek counter")
    return value


def text_field(value):
    if not isinstance(value, str) or not value.strip() or len(value) > 1024:
        raise ValueError("expected a nonempty Zeek string")
    return value


def optional(row, field, parser, issues):
    value = row.get(field)
    if value is None or value == "-":
        issues[field] = "missing"
        return None
    try:
        return parser(value)
    except (ValueError, ArithmeticError):
        issues[field] = "invalid"
        return None


@dataclass(frozen=True)
class Flow:
    timestamp_ns: int | None
    features: dict
    issues: dict
    endpoints: tuple

    @property
    def core_eligible(self):
        return self.features["proto"] in {"tcp", "udp"} and all(
            self.features[name] is not None for name in COUNTERS[:4]
        )

    def vector(self, fields):
        return json.dumps([self.features[name] for name in fields], ensure_ascii=True).encode("ascii")


def parse_flow(row):
    issues = {}
    timestamp = optional(row, "ts", seconds_ns, issues)
    features = {field: optional(row, field, count, issues) for field in COUNTERS}
    features.update({field: optional(row, field, text_field, issues) for field in TEXT_FIELDS})
    features["duration_ns"] = optional(row, "duration", duration_ns, issues)
    endpoints = tuple(row.get(field) for field in ("id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p"))
    return Flow(timestamp, features, issues, endpoints)


def read_flows(path, expected_hash):
    """Yield normalized rows while checking the exact file bytes and identity."""
    result = sha256()
    with path.open("rb") as stream:
        before = file_identity(fstat(stream.fileno()))
        for line_number, line in enumerate(iter(lambda: stream.readline(MAX_LINE + 1), b""), 1):
            if len(line) > MAX_LINE:
                raise ValueError(f"Zeek log line {line_number} exceeds 1 MiB")
            result.update(line)
            try:
                row = json.loads(line, parse_float=Decimal, parse_constant=Decimal)
                if not isinstance(row, dict):
                    raise ValueError("Zeek record must be an object")
            except (ValueError, RecursionError) as error:
                raise ValueError(f"invalid JSON Zeek record at line {line_number}") from error
            yield parse_flow(row)
        if (result.hexdigest() != expected_hash or before != file_identity(fstat(stream.fileno()))
                or before != file_identity(path.stat())):
            raise ValueError("Zeek log changed between registration and extraction")


class WindowLabels:
    """Apply reviewed window evidence using time only."""

    def __init__(self, windows, capture_bounds):
        self.windows = windows
        self.starts = [window.start for window in windows]
        self.bounds = capture_bounds

    def classify(self, flow):
        ts = flow.timestamp_ns
        if ts is None:
            return "unknown", None, "invalid_or_missing_start"
        if not self.bounds[0] <= ts < self.bounds[1]:
            return "unknown", None, "outside_capture"
        position = bisect_right(self.starts, ts) - 1
        if position < 0 or ts >= self.windows[position].end:
            return "unknown", None, "outside_reviewed_window"
        duration = flow.features["duration_ns"]
        if duration is None:
            return "unknown", None, "unverified_flow_end"
        window = self.windows[position]
        if ts + duration >= window.end:
            return "unknown", None, "crosses_reviewed_boundary"
        return window.label, window.category, "reviewed_window"
