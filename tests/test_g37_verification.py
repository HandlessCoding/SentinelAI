"""Check the G37 observer against fixed vectors and committed stream rows."""

import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from time import monotonic_ns

from sqlalchemy import event, select
from sqlalchemy.orm import Session
from test_investigations import PostgreSQLSchemaTestCase

from backend.models import ZeekFlow, ZeekStream
from backend.zeek_stream import Source, ingest_batch
from verification.g37 import flow_identity, load_manifest, persistence_upper_bound_ns

ROOT = Path(__file__).resolve().parents[1]
FIRST = b'{"uid":"CG37","ts":1700000000.123456789,"proto":"tcp"}\n'
SECOND = FIRST.replace(b"123456789", b"123456790")


class ObserverTests(unittest.TestCase):
    def test_pins_the_approved_fixture(self):
        manifest = load_manifest(ROOT)
        self.assertEqual(manifest["fixture"]["flows"], ["tcp", "tcp", "udp"])
        self.assertEqual(manifest["measurement"]["poll_ms"], 100)

    def test_nanosecond_identity_and_invalid_timestamp(self):
        identity = flow_identity(FIRST)
        self.assertEqual((identity.uid, identity.timestamp_ns), ("CG37", 1700000000123456789))
        self.assertNotEqual(identity.stream_key, flow_identity(SECOND).stream_key)
        for raw in (FIRST.replace(b"123456789", b"1234567891"), b'{"uid":"CG37"}'):
            with self.assertRaises(ValueError):
                flow_identity(raw)

    def test_conservative_monotonic_bound_requires_ordered_evidence(self):
        self.assertEqual(persistence_upper_bound_ns(120, 170, 200), 80)
        with self.assertRaises(ValueError):
            persistence_upper_bound_ns(180, 170, 200)


class CommittedIdentityTests(PostgreSQLSchemaTestCase):
    @unittest.skipUnless(sys.platform.startswith("linux"), "G37 retained-generation regression targets Linux")
    def test_interrupted_handoff_keeps_committed_evidence_until_restart(self):
        with TemporaryDirectory() as folder:
            active = Path(folder) / "conn.log"
            retained = active.with_suffix(".log.1")
            missing = active.with_suffix(".pending")
            active.write_bytes(FIRST)
            source = Source("g37-test", active, "session", "development", "fixture", "synthetic")

            def process():
                with Session(self.engine) as db:
                    return ingest_batch(db, source)

            def observe():
                with Session(self.engine) as reader:
                    state = reader.get(ZeekStream, source.capture_id)
                    keys = set(reader.scalars(select(ZeekFlow.stream_key)))
                    return state, keys

            process()
            before, first_keys = observe()
            with active.open("ab") as stream:
                stream.write(SECOND)
            info = active.stat()
            archive_bytes = active.read_bytes()
            archive_identity = f"{info.st_dev:x}:{info.st_ino:x}"
            active.rename(missing)
            third = FIRST.replace(b"123456789", b"123456791")
            active.write_bytes(FIRST + third[:-1])
            process()
            blocked, keys = observe()
            self.assertEqual(blocked.last_error, "rotated_file_missing")
            self.assertEqual(
                (blocked.file_identity, blocked.byte_offset, keys),
                (before.file_identity, before.byte_offset, first_keys),
            )

            missing.rename(retained)
            with Session(self.engine) as db:

                def interrupt(_):
                    raise RuntimeError("worker stopped before commit")

                event.listen(db, "before_commit", interrupt, once=True)
                with self.assertRaisesRegex(RuntimeError, "worker stopped"):
                    ingest_batch(db, source)
            unchanged, keys = observe()
            self.assertEqual(
                (unchanged.byte_offset, unchanged.last_drained_file, keys),
                (blocked.byte_offset, blocked.last_drained_file, first_keys),
            )

            process()
            process()
            partial, keys = observe()
            self.assertEqual(
                (partial.last_drained_file, partial.byte_offset, partial.duplicate_rows),
                (archive_identity, len(FIRST), 1),
            )
            self.assertEqual(keys, {flow_identity(raw).stream_key for raw in (FIRST, SECOND)})
            self.assertEqual(retained.read_bytes(), archive_bytes)
            self.assertEqual(retained.stat().st_ino, info.st_ino)
            last_incomplete = monotonic_ns()
            self.assertFalse(active.read_bytes().endswith(b"\n"))
            with active.open("ab") as stream:
                stream.write(b"\n")
            self.assertTrue(active.read_bytes().endswith(b"\n"))
            complete = monotonic_ns()
            process()
            finished, keys = observe()
            committed = monotonic_ns()
            self.assertGreaterEqual(persistence_upper_bound_ns(last_incomplete, complete, committed), 0)
            self.assertEqual((finished.byte_offset, finished.backlog_bytes), (active.stat().st_size, 0))
            self.assertEqual(keys, {flow_identity(raw).stream_key for raw in (FIRST, SECOND, third)})

    def test_one_row_per_source_and_precise_key(self):
        with TemporaryDirectory() as folder:
            path = Path(folder) / "conn.log"
            path.write_bytes(FIRST + SECOND + FIRST)
            for source_id in ("g37-synthetic-a", "g37-synthetic-b"):
                source = Source(source_id, path, source_id, "development", "fixture", "synthetic")
                with Session(self.engine) as db:
                    ingest_batch(db, source)
            expected = {
                (source_id, identity.stream_key, identity.timestamp_ns, "unknown")
                for source_id in ("g37-synthetic-a", "g37-synthetic-b")
                for identity in map(flow_identity, (FIRST, SECOND))
            }
            with Session(self.engine) as reader:
                flows = reader.execute(
                    select(
                        ZeekFlow.capture_id,
                        ZeekFlow.stream_key,
                        ZeekFlow.timestamp_ns,
                        ZeekFlow.ground_truth,
                    )
                ).all()
                states = reader.scalars(select(ZeekStream)).all()
            self.assertCountEqual(flows, expected)
            self.assertEqual(len(states), 2)
            for state in states:
                self.assertEqual((state.byte_offset, state.duplicate_rows), (path.stat().st_size, 1))
