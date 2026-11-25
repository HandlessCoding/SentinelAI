"""Verify packaged PostgreSQL, migrations and worker in the offline development container."""

import json
import os
import secrets
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path
from time import monotonic, sleep

from sqlalchemy import text

from backend.database import get_engine
from verification.g37 import flow_identity

SOURCE = "g37-offline-smoke"
REVISION = "0004_zeek_browsing"
CGROUP = Path("/sys/fs/cgroup")
ROW = b'{"uid":"CG37Offline","ts":1700000000.123456789,"proto":"tcp","conn_state":"SF"}\n'


def run(*args, **kwargs):
    return subprocess.run(args, check=True, timeout=30, text=True, **kwargs)


def execute_as_postgres(sql, database="postgres"):
    run(
        "runuser",
        "-u",
        "postgres",
        "--",
        "psql",
        "-X",
        "-q",
        "-v",
        "ON_ERROR_STOP=1",
        "-d",
        database,
        input=sql,
    )


def cpu_us():
    counters = dict(line.split() for line in (CGROUP / "cpu.stat").read_text().splitlines())
    return int(counters["usage_usec"])


def pg_listeners():
    result = []
    for table in ("tcp", "tcp6"):
        for line in (Path("/proc/net") / table).read_text().splitlines()[1:]:
            _, address, _, state, *_ = line.split()
            host, port = address.split(":")
            if state == "0A" and int(port, 16) == 5432:
                result.append((table, host))
    return result


@contextmanager
def worker(log):
    process = subprocess.Popen(
        [
            sys.executable,
            "-B",
            "-m",
            "backend.zeek_stream",
            SOURCE,
            str(log),
            "--environment",
            "development",
            "--observation-point",
            "synthetic",
            "--zeek-version",
            "synthetic",
        ],
        user="nobody",
        group="nogroup",
    )
    try:
        yield process
    finally:
        process.terminate()
        process.wait(timeout=10)


def checkpoint():
    with get_engine().connect() as connection:
        return connection.execute(
            text(
                "SELECT byte_offset, duplicate_rows, backlog_bytes, last_success_at "
                "FROM zeek_streams WHERE capture_id=:source"
            ),
            {"source": SOURCE},
        ).one_or_none()


def await_commit(process, offset, samples):
    deadline = monotonic() + 15
    while monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("Worker stopped before the expected commit")
        state = checkpoint()
        samples.append(int((CGROUP / "memory.current").read_text()))
        if state is not None and state.byte_offset == offset and state.backlog_bytes == 0:
            return state
        sleep(0.1)
    raise TimeoutError("Worker did not advance the committed checkpoint")


def assert_database():
    with get_engine().connect() as connection:
        observed = connection.execute(
            text(
                "SELECT current_user, host(inet_server_addr()), current_setting('server_version_num'), "
                "has_schema_privilege(current_user, 'public', 'CREATE'), "
                "(SELECT version_num FROM alembic_version)"
            )
        ).one()
        assert observed == ("g37_worker", "127.0.0.1", "160015", False, REVISION), observed
        assert pg_listeners() == [("tcp", "0100007F")]


def assert_flow():
    expected = flow_identity(ROW)
    with get_engine().connect() as connection:
        records = connection.execute(
            text("SELECT stream_key, timestamp_ns, ground_truth FROM zeek_flows WHERE capture_id=:source"),
            {"source": SOURCE},
        ).all()
    assert records == [(expected.stream_key, expected.timestamp_ns, "unknown")], records


def provision_roles():
    migration_password, worker_password = secrets.token_hex(24), secrets.token_hex(24)
    execute_as_postgres(
        f"CREATE ROLE g37_migrate LOGIN PASSWORD '{migration_password}';\n"
        f"CREATE ROLE g37_worker LOGIN PASSWORD '{worker_password}';\n"
        "CREATE DATABASE g37 OWNER g37_migrate;"
    )
    os.environ.update(SENTINELAI_DB_HOST="127.0.0.1", SENTINELAI_DB_PORT="5432", SENTINELAI_DB_NAME="g37")
    migration = dict(os.environ, SENTINELAI_DB_USER="g37_migrate", SENTINELAI_DB_PASSWORD=migration_password)
    run(sys.executable, "-B", "-m", "alembic", "upgrade", REVISION, env=migration)
    execute_as_postgres(
        "GRANT USAGE ON SCHEMA public TO g37_worker;\n"
        "GRANT SELECT ON alembic_version TO g37_worker;\n"
        "GRANT SELECT, INSERT, UPDATE ON zeek_captures, zeek_flows, zeek_streams TO g37_worker;",
        "g37",
    )
    os.environ.update(SENTINELAI_DB_USER="g37_worker", SENTINELAI_DB_PASSWORD=worker_password)


def disk_bytes(path):
    return int(run("du", "-sb", path, capture_output=True).stdout.split()[0])


def main():
    started, cpu_start = monotonic(), cpu_us()
    run("pg_ctlcluster", "16", "main", "start")
    provision_roles()
    assert_database()
    log = Path("/tmp/g37-smoke.log")
    log.write_bytes(ROW)
    samples = []
    with worker(log) as process:
        initial = await_commit(process, len(ROW), samples)
        assert_flow()
        assert initial.duplicate_rows == 0
    get_engine().dispose()
    run("pg_ctlcluster", "16", "main", "restart")
    assert_database()
    assert_flow()
    assert checkpoint() == initial
    with log.open("ab") as stream:
        stream.write(ROW)
    with worker(log) as process:
        resumed = await_commit(process, 2 * len(ROW), samples)
        assert_flow()
        assert resumed.duplicate_rows == 1
        assert resumed.last_success_at > initial.last_success_at
    print(
        "G37_SMOKE "
        + json.dumps(
            {
                "postgresql": "16.15",
                "listener": "127.0.0.1:5432 only",
                "migration": REVISION,
                "non_superuser_worker": True,
                "flows": 1,
                "duplicate_rows": 1,
                "snapshot_survived_postgres_restart": True,
                "checkpoint_offset": resumed.byte_offset,
                "wall_seconds": round(monotonic() - started, 3),
                "cpu_seconds": round((cpu_us() - cpu_start) / 1e6, 3),
                "runtime_sampled_peak_bytes": max(samples),
                "all_phases_cgroup_peak_bytes": int((CGROUP / "memory.peak").read_text()),
                "postgresql_data_bytes": disk_bytes("/var/lib/postgresql/16/main"),
                "venv_bytes": disk_bytes("/tmp/g37-venv"),
                "guest_limit_memory_bytes": int((CGROUP / "memory.max").read_text()),
                "kernel": "hosted Linux container kernel",
            },
            sort_keys=True,
        )
    )
    run("pg_ctlcluster", "16", "main", "stop")


if __name__ == "__main__":
    main()
