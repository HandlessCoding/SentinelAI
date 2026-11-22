"""Measure the synthetic stream on a disposable Linux database schema."""

import json
import os
import platform
import subprocess
import sys
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from statistics import median, quantiles
from tempfile import TemporaryDirectory
from threading import Event, current_thread
from time import monotonic_ns, process_time, sleep

from sqlalchemy import event, select
from sqlalchemy.orm import Session
from test_g37_browser import synthetic_predictions
from test_investigations import ROOT, PostgreSQLSchemaTestCase

from backend.models import ZeekFlow, ZeekStream
from backend.zeek_stream import Source, run_worker
from verification.g37 import flow_identity, persistence_upper_bound_ns

POLL_SECONDS = 0.025
CARDINALITIES = (10_000, 25_000)
PAGE_SIZES = (25, 100)
WORKER_THREAD = "g37-ingest"
PACE_BATCHES = 60
PACE_ROWS = 20


def synthetic_rows(first, total):
    return "".join(
        f'{{"uid":"CBenchmark{index}","ts":1700000000.{index:09},"proto":"tcp","conn_state":"SF"}}\n'
        for index in range(first, first + total)
    ).encode("ascii")


def latency_stats(samples):
    return {
        "p50_ms": round(median(samples) / 1e6, 3),
        "p95_ms": round(quantiles(samples, n=20, method="inclusive")[18] / 1e6, 3),
    }


@unittest.skipUnless(
    sys.platform.startswith("linux") and os.environ.get("SENTINELAI_G37_BENCHMARK") == "1",
    "opt-in synthetic Linux benchmark",
)
class SyntheticBenchmark(PostgreSQLSchemaTestCase):
    def test_sustained_ingestion_and_queries(self):
        import resource

        with (
            TemporaryDirectory() as folder,
            ThreadPoolExecutor(max_workers=1, thread_name_prefix=WORKER_THREAD) as pool,
        ):
            log = Path(folder) / "conn.log"
            log.touch()
            stop = Event()
            source = Source("g37-benchmark", log, "benchmark", "development", "fixture", "synthetic")
            started = monotonic_ns()
            worker = pool.submit(run_worker, self.engine, source, stop)
            try:
                ready, _ = self.wait_for_commit(worker, source, 0)
                cpu_started = process_time()
                lifecycle = self.measure_latency(log, source, worker)
                paced = self.measure_paced_input(log, source, worker)
                loads = self.measure_load(log, source, worker, 5 + PACE_BATCHES * PACE_ROWS)
                cpu_seconds = process_time() - cpu_started
            finally:
                stop.set()
                worker.result(timeout=10)
        with self.engine.connect() as connection:
            postgres = connection.exec_driver_sql("SHOW server_version").scalar_one()
            revision = connection.exec_driver_sql("SELECT version_num FROM alembic_version").scalar_one()
        report = {
            "scope": "synthetic Linux worker and PostgreSQL; process CPU and peak RSS include the test harness",
            "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
            "platform": platform.platform(),
            "python": platform.python_version(),
            "logical_cpus": os.cpu_count(),
            "postgres": postgres,
            "migration": revision,
            "poll_target_ms": POLL_SECONDS * 1000,
            "worker_start_to_first_committed_checkpoint_ms": round((ready - started) / 1e6, 3),
            "latency": lifecycle,
            "worker_and_harness_cpu_seconds": round(cpu_seconds, 3),
            "worker_and_harness_peak_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
            "paced_input": paced,
            "loads": loads,
        }
        print("G37_BENCHMARK " + json.dumps(report, sort_keys=True))

    def wait_for_commit(self, worker, source, offset, key=None):
        deadline = monotonic_ns() + 90_000_000_000
        observed_max = 0
        while monotonic_ns() < deadline:
            if worker.done():
                worker.result()
                self.fail("Benchmark worker stopped before commit")
            with Session(self.engine) as reader:
                state = reader.get(ZeekStream, source.capture_id)
                if state is not None:
                    observed_max = max(observed_max, state.backlog_bytes or 0)
                    if state.byte_offset == offset and state.backlog_bytes == 0:
                        if key is not None:
                            reader.scalars(
                                select(ZeekFlow.id).where(
                                    ZeekFlow.capture_id == source.capture_id,
                                    ZeekFlow.stream_key == key,
                                )
                            ).one()
                        return monotonic_ns(), observed_max
            sleep(POLL_SECONDS)
        self.fail(f"Benchmark worker did not commit offset {offset}")

    def measure_latency(self, log, source, worker):
        latencies = []
        visibility = []
        with self.make_client(synthetic_predictions) as http, ThreadPoolExecutor(max_workers=1) as api:
            for index in range(1, 6):
                row = synthetic_rows(index, 1)
                expected_key = flow_identity(row).stream_key
                with log.open("ab") as writer:
                    writer.write(row[:-1])
                last_incomplete = monotonic_ns()
                with log.open("rb") as reader:
                    reader.seek(-1, os.SEEK_END)
                    self.assertNotEqual(reader.read(), b"\n")
                visible = api.submit(self.wait_for_api, http, index)
                with log.open("ab") as writer:
                    writer.write(b"\n")
                with log.open("rb") as reader:
                    reader.seek(-1, os.SEEK_END)
                    self.assertEqual(reader.read(), b"\n")
                complete = monotonic_ns()
                committed, _ = self.wait_for_commit(worker, source, log.stat().st_size, expected_key)
                latencies.append(persistence_upper_bound_ns(last_incomplete, complete, committed))
                visibility.append(max(complete, visible.result(timeout=10)) - last_incomplete)
        return {"committed_read": latency_stats(latencies), "independent_api_read": latency_stats(visibility)}

    def wait_for_api(self, http, source_row):
        deadline = monotonic_ns() + 10_000_000_000
        while monotonic_ns() < deadline:
            page = http.get("/traffic/flows", params={"limit": 1}).raise_for_status().json()
            if page["flows"] and page["flows"][0]["source_row"] == source_row:
                return monotonic_ns()
            sleep(POLL_SECONDS)
        self.fail(f"Expected synthetic source row {source_row} did not become visible through FastAPI")

    def measure_paced_input(self, log, source, worker):
        started = monotonic_ns()
        samples = []
        for batch in range(PACE_BATCHES):
            remaining_ns = started + batch * 100_000_000 - monotonic_ns()
            sleep(max(0, remaining_ns) / 1e9)
            with log.open("ab") as writer:
                writer.write(synthetic_rows(6 + batch * PACE_ROWS, PACE_ROWS))
            if (batch + 1) % 5 == 0:
                with Session(self.engine) as reader:
                    state = reader.get(ZeekStream, source.capture_id)
                    samples.append(
                        {
                            "elapsed_ms": round((monotonic_ns() - started) / 1e6, 3),
                            "appended_flows": (batch + 1) * PACE_ROWS,
                            "committed_flows": state.rows_seen
                            - state.rejected_rows
                            - state.duplicate_rows
                            - 5,
                            "uncommitted_bytes": log.stat().st_size - state.byte_offset,
                        }
                    )
        appended = monotonic_ns()
        committed, observed_worker = self.wait_for_commit(worker, source, log.stat().st_size)
        total = PACE_BATCHES * PACE_ROWS
        paced_duration = (appended - started) / 1e9 + 0.1
        self.assertEqual(self.count(ZeekFlow), 5 + total)
        return {
            "target_flows_per_second": 200,
            "flows": total,
            "window_seconds": round(paced_duration, 3),
            "delivered_flows_per_second": round(total / paced_duration, 2),
            "commits_per_second_until_drained": round(total * 1e9 / (committed - started), 2),
            "max_sampled_uncommitted_bytes": max(sample["uncommitted_bytes"] for sample in samples),
            "max_observed_worker_backlog_bytes": observed_worker,
            "samples": samples,
        }

    def measure_load(self, log, source, worker, rows):
        results = []
        for total in CARDINALITIES:
            payload = synthetic_rows(rows + 1, total - rows)
            started = monotonic_ns()
            with log.open("ab") as writer:
                writer.write(payload)
            committed, backlog = self.wait_for_commit(worker, source, log.stat().st_size)
            self.assertEqual(self.count(ZeekFlow), total)
            with self.engine.connect() as connection:
                relation_bytes = connection.exec_driver_sql(
                    "SELECT pg_total_relation_size('zeek_flows')"
                ).scalar_one()
            results.append(
                {
                    "rows": total,
                    "appended_bytes": len(payload),
                    "database_flow_relation_and_indexes_bytes": relation_bytes,
                    "max_observed_worker_backlog_bytes": backlog,
                    "burst_commits_per_second": round((total - rows) * 1e9 / (committed - started), 2),
                    "queries": self.measure_queries(),
                }
            )
            rows = total
        return results

    def measure_queries(self):
        with self.make_client(synthetic_predictions) as http:
            first = http.get("/traffic/flows", params={"limit": 25}).raise_for_status().json()["flows"][0]
            cases = [("summary", "/traffic/summary", {}), ("detail", f"/traffic/flows/{first['id']}", {})]
            for order in ("observed", "ingested"):
                for size in PAGE_SIZES:
                    query = {
                        "limit": size,
                        "order": order,
                        "pagination": "cursor",
                        "capture_id": "g37-benchmark",
                        "protocol": "tcp",
                    }
                    cursor = http.get("/traffic/flows", params=query).raise_for_status().json()["next_cursor"]
                    self.assertIsNotNone(cursor)
                    cases.extend(
                        [
                            (f"{order}-{size}-first", "/traffic/flows", query),
                            (f"{order}-{size}-next", "/traffic/flows", dict(query, cursor=cursor)),
                        ]
                    )
            return {name: self.measure_request(http, route, params) for name, route, params in cases}

    def measure_request(self, http, route, params):
        statements = []

        def capture(_connection, _cursor, statement, parameters, _context, _many):
            if not current_thread().name.startswith(WORKER_THREAD) and statement.lstrip().upper().startswith(
                "SELECT "
            ):
                statements.append((statement, parameters))

        event.listen(self.engine, "before_cursor_execute", capture)
        try:
            http.get(route, params=params).raise_for_status()
        finally:
            event.remove(self.engine, "before_cursor_execute", capture)
        self.assertTrue(statements)
        samples = []
        for _ in range(10):
            started = monotonic_ns()
            http.get(route, params=params).raise_for_status()
            samples.append(monotonic_ns() - started)
        with self.engine.connect() as connection:
            plans = [
                connection.exec_driver_sql(
                    "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) " + sql, args
                ).scalar_one()[0]
                for sql, args in statements
            ]
        return {
            "api": latency_stats(samples),
            "postgres_execution_ms": round(sum(plan["Execution Time"] for plan in plans), 3),
            "postgres_shared_hit_blocks": sum(plan["Plan"]["Shared Hit Blocks"] for plan in plans),
            "postgres_shared_read_blocks": sum(plan["Plan"]["Shared Read Blocks"] for plan in plans),
            "postgres_plan_nodes": [self.plan_nodes(plan["Plan"]) for plan in plans],
        }

    def plan_nodes(self, plan):
        fields = ("Node Type", "Index Name", "Relation Name", "Sort Method", "Actual Rows")
        node = {field: plan[field] for field in fields if field in plan}
        if "Plans" in plan:
            node["children"] = [self.plan_nodes(child) for child in plan["Plans"]]
        return node
