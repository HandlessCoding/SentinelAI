"""Seal local capture manifests and evidence without changing recordings."""

from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
import json
from os import fstat
from pathlib import Path
import re

from ml.audit_iot23_captures import ROLES
from ml.audit_level2_data import file_identity


DEFAULT_ROOT = Path("data/level2/capture-lab")
NANOSECOND = 1_000_000_000
EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
SOURCES = {"synthetic", "authorized_lab", "authorized_archive"}
PCAP_HEADERS = {bytes.fromhex(header) for header in (
    "a1b2c3d4", "d4c3b2a1", "a1b23c4d", "4d3cb2a1", "0a0d0d0a",
)}
ZEEK_SETTINGS = ("LogAscii::use_json=T", "use_conn_size_analyzer=T")


def identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", value):
        raise ValueError("expected a lowercase identifier with up to 64 characters")
    return value


def utc_ns(value):
    if not isinstance(value, str) or not re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,6})?Z", value
    ):
        raise ValueError("expected an ISO-8601 UTC timestamp ending in Z")
    interval = datetime.fromisoformat(value) - EPOCH
    return (interval.days * 86_400 + interval.seconds) * NANOSECOND + interval.microseconds * 1000


def lab_path(root, name):
    """Resolve manifest paths under the lab root, including symlink targets."""
    if not isinstance(name, str) or not name or ":" in name or "\\" in name:
        raise ValueError("expected a relative lab path using forward slashes")
    relative = Path(name)
    if relative.is_absolute() or ".." in relative.parts or not relative.parts:
        raise ValueError("expected a relative lab path using forward slashes")
    path = (root / relative).resolve()
    if not path.is_relative_to(root.resolve()):
        raise ValueError("path escapes the lab root")
    return path


def read_object(path):
    with path.open("rb") as stream:
        blob = stream.read(1024**2 + 1)
    if len(blob) > 1024**2:
        raise ValueError("manifest or receipt exceeds 1 MiB")
    obj = json.loads(blob)
    if not isinstance(obj, dict):
        raise ValueError("expected a JSON object")
    return obj


def write_new_object(path, obj):
    content = json.dumps(obj, sort_keys=True, indent=2, allow_nan=False) + "\n"
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(content)


def digest(path, *, pcap=False, max_bytes=None):
    """Hash one file and reject source changes observed during the read."""
    with path.open("rb") as stream:
        stat = fstat(stream.fileno())
        if max_bytes is not None and stat.st_size > max_bytes:
            raise ValueError("capture artifact exceeds the import size limit")
        before = file_identity(stat)
        if pcap:
            if stream.read(4) not in PCAP_HEADERS:
                raise ValueError("expected a PCAP or PCAPNG file header")
            stream.seek(0)
        result = sha256()
        for block in iter(lambda: stream.read(1024**2), b""):
            if max_bytes is not None and stream.tell() > max_bytes:
                raise ValueError("capture artifact exceeds the import size limit")
            result.update(block)
        if before != file_identity(fstat(stream.fileno())) or before != file_identity(path.stat()):
            raise ValueError("source file changed while hashing")
    return result.hexdigest()


def time_bounds(obj):
    start, end = utc_ns(obj["start"]), utc_ns(obj["end"])
    if start >= end:
        raise ValueError("capture and label windows require increasing UTC bounds")
    return start, end


@dataclass(frozen=True)
class LabelWindow:
    start: int
    end: int
    label: str
    category: str | None


def validate_spec(spec):
    required = {
        "version", "capture_id", "session_id", "environment_id", "device_ids",
        "observation_point", "collection_profile", "scenario", "source", "role",
        "start", "end", "pcap", "conn_log", "windows",
    }
    if not required.issubset(spec) or spec.keys() - required - {"zeek_receipt", "authorization", "evidence_files"}:
        raise ValueError("unexpected or missing capture manifest fields")
    if type(spec["version"]) is not int or spec["version"] != 1:
        raise ValueError("unsupported capture manifest version")
    if spec["source"] not in SOURCES or spec["role"] not in ROLES:
        raise ValueError("unsupported capture source or role")
    for field in ("capture_id", "session_id", "environment_id", "observation_point",
                  "collection_profile", "scenario"):
        identifier(spec[field])
    devices = spec["device_ids"]
    if not isinstance(devices, list) or not devices or len({identifier(item) for item in devices}) != len(devices):
        raise ValueError("device_ids must contain unique device identifiers")
    if spec["source"] != "synthetic" and not {"zeek_receipt", "authorization"} <= spec.keys():
        raise ValueError("authorized captures require an offline Zeek receipt and permission record")
    evidence_files = spec.get("evidence_files", [])
    if (not isinstance(evidence_files, list)
            or any(not isinstance(name, str) or not name.strip() for name in evidence_files)
            or len(set(evidence_files)) != len(evidence_files)):
        raise ValueError("evidence_files must contain distinct lab paths")
    start, end = time_bounds(spec)
    windows = []
    if not isinstance(spec["windows"], list):
        raise ValueError("windows must be a list")
    for window in spec["windows"]:
        fields = {"start", "end", "label", "evidence", "evidence_kind", "author", "reviewer", "scope"}
        if not isinstance(window, dict) or not fields.issubset(window) or window.keys() - fields - {"category"}:
            raise ValueError("unexpected or missing label-window fields")
        left, right = time_bounds(window)
        if not start <= left < right <= end or (windows and left < windows[-1].end):
            raise ValueError("label windows must be ordered and disjoint within the capture")
        label = window["label"]
        if label not in ("benign", "attack") or window["scope"] != "all_observed_flows":
            raise ValueError("a label window requires reviewed evidence for all observed flows")
        valid_kinds = {"scenario_event_log", "independent_annotation"}
        if spec["source"] == "synthetic":
            valid_kinds.add("synthetic_fixture")
        if window["evidence_kind"] not in valid_kinds:
            raise ValueError("unsupported independent evidence kind")
        if identifier(window["author"]) == identifier(window["reviewer"]):
            raise ValueError("evidence author and reviewer must be distinct")
        category = window.get("category")
        if label == "attack":
            identifier(category)
        elif category is not None:
            raise ValueError("only attack windows accept a category")
        windows.append(LabelWindow(left, right, label, category))
    return windows


def verified_hashes(root, spec, *, max_artifact_bytes=None):
    paths = {"pcap": spec["pcap"], "conn_log": spec["conn_log"]}
    paths.update({name: spec[name] for name in ("authorization", "zeek_receipt") if name in spec})
    resolved = {name: lab_path(root, path) for name, path in paths.items()}
    if len(set(resolved.values())) != len(resolved):
        raise ValueError("capture, log, permission record, and receipt must be distinct files")
    evidence_hashes = {}
    names = dict.fromkeys([*spec.get("evidence_files", []), *(window["evidence"] for window in spec["windows"])])
    if max_artifact_bytes is not None and len(names) > 32:
        raise ValueError("capture exceeds the import limit of 32 evidence files")
    max_metadata = min(max_artifact_bytes, 1024**2) if max_artifact_bytes is not None else None
    for name in names:
        path = lab_path(root, name)
        if path in resolved.values() or not path.is_file() or path.stat().st_size == 0:
            raise ValueError("label evidence must be a separate nonempty file")
        evidence_hashes[name] = digest(path, max_bytes=max_metadata)
    if "authorization" in resolved and resolved["authorization"].stat().st_size == 0:
        raise ValueError("permission record is empty")
    hashes = {name: digest(path, pcap=name == "pcap",
                           max_bytes=max_artifact_bytes if name in {"pcap", "conn_log"} else max_metadata)
              for name, path in resolved.items()}
    if "zeek_receipt" in resolved:
        receipt = read_object(resolved["zeek_receipt"])
        if (receipt.get("version") != 1 or receipt.get("settings") != list(ZEEK_SETTINGS)
                or receipt.get("pcap_sha256") != hashes["pcap"]
                or receipt.get("conn_sha256") != hashes["conn_log"]
                or not isinstance(receipt.get("zeek_version"), str) or not receipt["zeek_version"].strip()):
            raise ValueError("offline Zeek receipt does not match the capture and log")
    return {**hashes, "evidence": evidence_hashes}


def manifest_path(root, capture_id):
    return lab_path(root, f"registry/{identifier(capture_id)}.json")


def register(root, spec):
    validate_spec(spec)
    path = manifest_path(root, spec["capture_id"])
    if path.exists():
        raise FileExistsError("capture ID is already registered")
    manifest = {"capture": spec, "sha256": verified_hashes(root, spec)}
    path.parent.mkdir(parents=True, exist_ok=True)
    write_new_object(path, manifest)
    return path


def load_verified(root, capture_id, *, max_artifact_bytes=None):
    manifest = read_object(manifest_path(root, capture_id))
    spec = manifest["capture"]
    windows = validate_spec(spec)
    if (spec["capture_id"] != capture_id
            or manifest["sha256"] != verified_hashes(root, spec, max_artifact_bytes=max_artifact_bytes)):
        raise ValueError(f"{capture_id} manifest or artifact checksum mismatch")
    return manifest, windows
