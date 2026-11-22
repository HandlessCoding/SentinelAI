"""Continuously ingest a local Zeek JSON log into PostgreSQL."""

import argparse
from contextlib import ExitStack
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import sys
from threading import Event

from sqlalchemy import select, text
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from backend.database import DatabaseConfigurationError, get_engine
from backend.models import ZeekCapture, ZeekFlow, ZeekStream
from backend.zeek_ingest import MAX_ARTIFACT_BYTES, MAX_ROWS, flow_values
from ml.lab_capture import capture_rows
from ml.lab_registry import identifier, lab_path, load_verified, read_object
from ml.lab_zeek import parse_flow


MAX_LINE_BYTES = 64 * 1024
MAX_BATCH_BYTES = 256 * 1024
MAX_BATCH_ROWS = 128
ANCHOR_BYTES = 256


@dataclass(frozen=True)
class Source:
    capture_id: str
    path: Path
    session_id: str
    environment_id: str
    observation_point: str
    zeek_version: str
    replay_capture_id: str | None = None
    replay_conn_sha256: str | None = None
    replay_manifest_sha256: str | None = None
    labels: dict = field(default_factory=dict, repr=False)

    @property
    def kind(self):
        return "recorded_replay" if self.replay_capture_id is not None else "connected_sensor"

    @property
    def config_sha256(self):
        return fingerprint([
            self.capture_id, str(self.path), self.session_id, self.environment_id,
            self.observation_point, self.zeek_version, self.kind, self.replay_capture_id,
            self.replay_conn_sha256, self.replay_manifest_sha256,
        ])


def fingerprint(values):
    return sha256(json.dumps(values, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def local_path(path):
    if str(path).startswith(("\\\\", "//")):
        raise ValueError("expected a local path")
    resolved = path.parent.resolve() / path.name
    if str(resolved).startswith(("\\\\", "//")):
        raise ValueError("expected a local path")
    return resolved


def replay_source(source_id, path, root, capture_id):
    """Bind labels to exact verified Zeek lines from a registered recording."""
    manifest, windows = load_verified(root, capture_id, max_artifact_bytes=MAX_ARTIFACT_BYTES)
    spec, hashes = manifest["capture"], manifest["sha256"]
    if spec["source"] == "synthetic":
        raise ValueError("replay requires an authorized recording")
    original = lab_path(root, spec["conn_log"])
    if path == original or (path.exists() and path.samefile(original)):
        raise ValueError("use a disposable replay log")
    receipt = read_object(lab_path(root, spec["zeek_receipt"]))
    labels, checksum = {}, sha256()
    rows = capture_rows(root, manifest, windows, max_log_bytes=MAX_ARTIFACT_BYTES)
    with original.open("rb") as stream:
        for index, (raw, (_, label)) in enumerate(zip(
            iter(lambda: stream.readline(MAX_LINE_BYTES + 1), b""), rows, strict=True
        ), 1):
            if index > MAX_ROWS or len(raw) > MAX_LINE_BYTES:
                raise ValueError("replay recording exceeds the worker limits")
            checksum.update(raw)
            labels[sha256(raw.rstrip(b"\r\n")).hexdigest()] = label
    if checksum.hexdigest() != hashes["conn_log"]:
        raise ValueError("replay recording changed during verification")
    return Source(source_id, path, spec["session_id"], spec["environment_id"], spec["observation_point"],
                  receipt["zeek_version"], capture_id, hashes["conn_log"], fingerprint(manifest), labels)


def open_log(path):
    if not stat.S_ISREG(path.lstat().st_mode):
        raise OSError("expected a regular local log")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0)
                         | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or not info.st_ino:
            raise OSError("expected an identifiable regular file")
        return os.fdopen(descriptor, "rb"), f"{info.st_dev:x}:{info.st_ino:x}", info.st_size
    except BaseException:
        os.close(descriptor)
        raise


def checkpoint_anchor(stream, offset):
    if offset == 0:
        return None
    count = min(offset, ANCHOR_BYTES)
    stream.seek(offset - count)
    data = stream.read(count)
    if len(data) != count:
        raise OSError("log shortened while reading")
    return sha256(data).hexdigest()


def read_batch(stream, offset, size, discarding, *, retired):
    """Read at most one batch and retain an unfinished ordinary line on disk."""
    records = []
    stop = min(size, offset + MAX_BATCH_BYTES)
    stream.seek(offset)
    while offset < stop and len(records) < MAX_BATCH_ROWS:
        start = offset
        raw = stream.readline(min(MAX_LINE_BYTES + 1, stop - offset))
        if not raw:
            raise OSError("log shortened while reading")
        end = stream.tell()
        if raw.endswith(b"\n"):
            records.append((start, None if discarding or len(raw) > MAX_LINE_BYTES else raw))
            discarding = False
        elif retired and end == size:
            records.append((start, None))
            discarding = False
        elif discarding or len(raw) > MAX_LINE_BYTES:
            discarding = True
        else:
            break
        offset = end
    if retired and offset == size and discarding:
        if len(records) < MAX_BATCH_ROWS:
            records.append((offset, None))
            discarding = False
    return records, offset, discarding


def prepare_row(source, index, file_identity, offset, raw, now):
    row = json.loads(raw, parse_float=Decimal, parse_constant=Decimal)
    if not isinstance(row, dict):
        raise ValueError("expected an object")
    flow = parse_flow(row)
    if source.kind == "recorded_replay":
        key = sha256(raw.rstrip(b"\r\n")).hexdigest()
        label = source.labels.get(key)
        if label is None:
            raise ValueError("row does not match verified replay")
    else:
        uid = row.get("uid")
        if not isinstance(uid, str) or not 1 <= len(uid) <= 128 or not uid.isascii() or not uid.isalnum():
            raise ValueError("expected a Zeek UID")
        key = fingerprint([uid, flow.timestamp_ns])
        label = ("unknown", None, "unreviewed_stream")
    return dict(flow_values(source.capture_id, index, flow, label), stream_key=key,
                source_file=file_identity, source_offset=offset, ingested_at=now)


def register_source(db, source):
    db.execute(insert(ZeekCapture).values(
        capture_id=source.capture_id, session_id=source.session_id, environment_id=source.environment_id,
        observation_point=source.observation_point, zeek_version=source.zeek_version, source=source.kind,
        manifest_sha256=source.config_sha256, flow_count=0,
    ).on_conflict_do_nothing())
    capture = db.get(ZeekCapture, source.capture_id)
    if capture.manifest_sha256 != source.config_sha256 or capture.source != source.kind:
        raise ValueError("source ID already has different provenance")
    db.execute(insert(ZeekStream).values(capture_id=source.capture_id, replay_capture_id=source.replay_capture_id,
               replay_conn_sha256=source.replay_conn_sha256).on_conflict_do_nothing())


def stopped(checkpoint, status, error):
    checkpoint.status = status
    checkpoint.last_error = error
    checkpoint.backlog_bytes = None
    return 0


def consume(db, source, checkpoint, stream, identity, size, *, old, next_file, now):
    lag = next_file[2] if old and next_file else 0
    offset = checkpoint.byte_offset
    if size < offset or checkpoint_anchor(stream, offset) != checkpoint.anchor:
        return stopped(checkpoint, "blocked", "checkpoint_content_changed")
    records, end, discarding = read_batch(stream, offset, size, checkpoint.discarding,
                                         retired=old and next_file is not None)
    anchor = checkpoint_anchor(stream, end)
    available = os.fstat(stream.fileno()).st_size
    if available < end or checkpoint_anchor(stream, offset) != checkpoint.anchor:
        return stopped(checkpoint, "blocked", "checkpoint_content_changed")
    rows = []
    for position, raw in records:
        checkpoint.rows_seen += 1
        try:
            if raw is None:
                raise ValueError("oversized or incomplete rotated row")
            rows.append(prepare_row(source, checkpoint.rows_seen, identity, position, raw, now))
        except (ValueError, ArithmeticError, RecursionError):
            checkpoint.rejected_rows += 1
            checkpoint.last_error = "rejected_record"
    inserted = 0
    if rows:
        inserted = len(db.scalars(insert(ZeekFlow).values(rows).on_conflict_do_nothing(
            constraint="uq_zeek_flows_stream_key").returning(ZeekFlow.id)).all())
        checkpoint.capture.flow_count += inserted
        checkpoint.duplicate_rows += len(rows) - inserted
        if inserted:
            checkpoint.last_ingested_at = now
    checkpoint.file_identity, checkpoint.byte_offset, checkpoint.anchor = identity, end, anchor
    checkpoint.discarding = discarding
    if old and next_file and end == available and not discarding:
        checkpoint.file_identity, checkpoint.byte_offset, checkpoint.anchor = next_file[1], 0, None
    checkpoint.backlog_bytes = available - end + lag
    checkpoint.status = "waiting" if old and next_file is None else "ready"
    checkpoint.last_success_at = now
    return end - offset


def ingest_batch(db, source):
    """Commit a bounded file slice, its flow inserts and health as one transaction."""
    with db.begin(), ExitStack() as files:
        db.execute(text("SET LOCAL statement_timeout = '5s'"))
        register_source(db, source)
        checkpoint = db.scalar(select(ZeekStream).where(
            ZeekStream.capture_id == source.capture_id).with_for_update())
        now = datetime.now(UTC)
        checkpoint.heartbeat_at = now
        try:
            current = open_log(source.path)
            files.enter_context(current[0])
        except OSError:
            current = None
        old = checkpoint.file_identity is not None and (current is None or current[1] != checkpoint.file_identity)
        active = current
        if old:
            try:
                active = open_log(source.path.with_name(source.path.name + ".1"))
                files.enter_context(active[0])
            except OSError:
                return stopped(checkpoint, "blocked" if current else "waiting",
                               "rotated_file_missing" if current else "source_unavailable")
            if active[1] != checkpoint.file_identity:
                return stopped(checkpoint, "blocked", "rotated_file_identity_changed")
        if active is None:
            return stopped(checkpoint, "waiting", "source_unavailable")
        try:
            return consume(db, source, checkpoint, *active, old=old, next_file=current, now=now)
        except OSError:
            return stopped(checkpoint, "waiting", "source_read_failed")


def run_worker(engine, source, stop):
    """Process one configured source until shutdown, with a single batch in flight."""
    while not stop.is_set():
        try:
            with Session(engine) as db:
                consumed = ingest_batch(db, source)
        except SQLAlchemyError:
            print("Zeek ingestion waiting for PostgreSQL. Check local database and migrations.", file=sys.stderr)
            consumed = 0
        stop.wait(0.05 if consumed else 1)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source_id", type=identifier)
    parser.add_argument("log", type=Path)
    parser.add_argument("--replay-root", type=Path)
    parser.add_argument("--capture-id", type=identifier)
    parser.add_argument("--environment", type=identifier)
    parser.add_argument("--observation-point", type=identifier)
    parser.add_argument("--zeek-version")
    args = parser.parse_args(argv)
    try:
        path = local_path(args.log)
        if args.replay_root is not None and args.capture_id and not any(
            (args.environment, args.observation_point, args.zeek_version)
        ):
            source = replay_source(args.source_id, path, local_path(args.replay_root), args.capture_id)
        elif args.replay_root is None and args.capture_id is None and args.environment and args.observation_point:
            source = Source(args.source_id, path, args.source_id, args.environment,
                            args.observation_point, args.zeek_version or "")
        else:
            raise ValueError("incomplete source configuration")
        if not 1 <= len(source.zeek_version) <= 128 or not source.zeek_version.isprintable():
            raise ValueError("invalid Zeek version")
        engine = get_engine()
    except (DatabaseConfigurationError, OSError, ValueError, KeyError, TypeError):
        parser.exit(2, "Check source provenance, local log path, replay receipt and database settings.\n")
    try:
        run_worker(engine, source, Event())
    except ValueError:
        parser.exit(2, "This source ID is already bound to different provenance.\n")
    except KeyboardInterrupt:
        return


if __name__ == "__main__":
    main()
