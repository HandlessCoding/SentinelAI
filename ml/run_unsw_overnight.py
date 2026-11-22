"""Run, resume, and inspect G32.1 using only the pinned G32 fitting rows."""

import argparse
from contextlib import contextmanager
from datetime import UTC, datetime
from hashlib import sha256
from importlib.metadata import version
import json
import os
from pathlib import Path
import platform
from statistics import mean
from threading import Event, Thread
from time import process_time, sleep, time
from uuid import uuid4

from threadpoolctl import threadpool_limits

from ml.run_baseline import DEPENDENCIES
from ml.run_unsw_development import RECALL_FLOOR, peak_rss_bytes, sha256_file
from ml.unsw_overnight_data import (FEATURE_SETS, FOLD_COUNT, FOLD_SEED, G32_ARCHIVE_SHA256,
                                   SMOKE_SEED, column_positions, load_overnight_data, plan_folds)
from ml.unsw_overnight_models import (FOREST_WORKERS, IMPORTANCE_ROWS, IMPORTANCE_SEED, MONITORED_FIELDS,
                                     NATIVE_THREADS, aggregate_folds, configurations, fit_fold, rank_candidates, spread)


DEFAULT_OUTPUT = Path("data/g32-1-overnight")
MEMORY_BYTES = 8 * 1024**3
TIME_SECONDS = 8 * 60 * 60


class Halt(RuntimeError):
    """Stop without marking a partially evaluated configuration as failed."""


def utc_stamp(value=None):
    return datetime.fromtimestamp(time() if value is None else value, UTC).isoformat()


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def write_atomic(path, document):
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as stream:
        json.dump(document, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    for attempt in range(5):
        try:
            temporary.replace(path)
            return
        except PermissionError:
            if attempt == 4:
                raise
            sleep(0.05)


def log_event(directory, event, **details):
    with (directory / "events.jsonl").open("a", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps({"at": utc_stamp(), "event": event, **details}, allow_nan=False) + "\n")


@contextmanager
def run_lock(directory):
    """The OS releases this lock even if an interrupted worker exits abruptly."""
    with (directory / "run.lock").open("a+b") as lock:
        if not lock.tell():
            lock.write(b"\0")
            lock.flush()
        lock.seek(0)
        if os.name == "nt":
            import msvcrt

            try:
                msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError as error:
                raise BlockingIOError("A worker already owns this run directory") from error
        else:
            import fcntl

            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield


def is_active(directory):
    try:
        with run_lock(directory):
            return False
    except BlockingIOError:
        return True


def plan_for_run(smoke):
    files = ("run_unsw_overnight.py", "unsw_overnight_data.py", "unsw_overnight_models.py",
             "run_unsw_development.py", "run_baseline.py", "run_model_comparison.py", "unsw_development_split.py")
    return {
        "smoke": smoke, "configurations": configurations(smoke=smoke), "feature_sets": FEATURE_SETS,
        "g32_archive_sha256": G32_ARCHIVE_SHA256, "recall_floor": RECALL_FLOOR, "fold_seed": FOLD_SEED,
        "smoke_seed": SMOKE_SEED, "importance_seed": IMPORTANCE_SEED, "importance_rows_per_fold": IMPORTANCE_ROWS,
        "rotations": FOLD_COUNT, "native_threads": NATIVE_THREADS, "forest_workers": FOREST_WORKERS,
        "runtime_seconds": 300 if smoke else TIME_SECONDS, "memory_limit_bytes": MEMORY_BYTES,
        "versions": {"python": platform.python_version(), **{name: version(name) for name in DEPENDENCIES}},
        "source_sha256": {name: sha256_file(Path(__file__).with_name(name)) for name in files},
    }


def run_manifest(directory, smoke):
    path = directory / "plan.json"
    plan = plan_for_run(smoke)
    signature = sha256(json.dumps(plan, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    if path.is_file():
        manifest = read_json(path)
        if manifest["plan_sha256"] != signature:
            raise ValueError("The saved experiment plan differs. Resume with the original code, runtime, and mode.")
        return manifest
    started = time()
    manifest = {"started_at": utc_stamp(started), "deadline_epoch": started + plan["runtime_seconds"],
                "plan": plan, "plan_sha256": signature}
    write_atomic(path, manifest)
    return manifest


def limit_reason(deadline):
    if time() >= deadline:
        return "wall-clock deadline reached"
    peak = peak_rss_bytes()
    if peak is None:
        return "resident memory measurement unavailable"
    if peak >= MEMORY_BYTES:
        return "8 GiB peak resident memory cap reached"
    return None


def watchdog(directory, deadline, attempt, finished):
    """Enforce the hard ceilings even while a native estimator is fitting."""
    while not finished.is_set():
        reason = limit_reason(deadline)
        if reason:
            try:
                write_atomic(directory / f"interrupt-{attempt}.json", {"reason": reason, "at": utc_stamp(),
                             "peak_process_rss_bytes": peak_rss_bytes(), "worker_pid": os.getpid()})
            finally:
                os._exit(2)  # Completed fold checkpoints were published atomically.
        finished.wait(max(0, min(2, deadline - time())))


def checkpoint(directory, config):
    path = directory / "configs" / f"{config['id']}.json"
    if not path.is_file():
        return path, {"config": config, "status": "pending", "folds": []}
    result = read_json(path)
    if (result["config"] != config or [row["fold"] for row in result["folds"]] != list(range(1, len(result["folds"]) + 1))
            or len(result["folds"]) > FOLD_COUNT or (result["status"] == "completed" and len(result["folds"]) != FOLD_COUNT)):
        raise ValueError(f"Invalid checkpoint for {config['id']}")
    return path, result


def report_run(directory, manifest):
    results = [checkpoint(directory, item)[1] for item in manifest["plan"]["configurations"]]
    completed = rank_candidates([item for item in results if item["status"] == "completed"])
    best = completed[0] if completed else None
    comparison = []
    for full in completed:
        if full["config"]["feature_set"] != "full":
            continue
        recipe = full["config"]["recipe"]
        paired = [item for item in completed if item["config"]["recipe"] == recipe]
        effects = {}
        for item in paired:
            feature_set = item["config"]["feature_set"]
            if feature_set != "full":
                effects[feature_set] = {
                    metric: spread([ablated["calibrated"][metric] - reference["calibrated"][metric]
                                    for ablated, reference in zip(item["folds"], full["folds"], strict=True)])
                    for metric in ("recall", "false_positive_rate")
                }
        comparison.append({"recipe": recipe, "feature_sets": {
            item["config"]["feature_set"]: item["aggregate"]["calibrated"] for item in paired
        }, "paired_deltas_from_full": effects, "watched_feature_importance": full["importance"]["watched_fields"]})
    state_path = directory / "state.json"
    return {
        "scope": "exploratory rotated evaluation within the original G32 fitting partition",
        "threshold_rule": "choose calibration-only minimum FPR at recall >= 0.95; scores equal to threshold count as attacks",
        "variability": "mean, sample standard deviation and range over overlapping-training folds, not confidence intervals",
        "plan_sha256": manifest["plan_sha256"], "deadline_utc": utc_stamp(manifest["deadline_epoch"]),
        "run_state": read_json(state_path) if state_path.is_file() else None,
        "completed": completed, "other_configurations": [item for item in results if item["status"] != "completed"],
        "full_vs_ablated": comparison, "best_exploratory_candidate": best["config"]["id"] if best else None,
        "best_met_recall_in_every_fold": (best["aggregate"]["calibrated"]["recall"]["min"] >= RECALL_FLOOR) if best else None,
        "resource_interrupts": [read_json(path) for path in sorted(directory.glob("interrupt-*.json"))],
        "g33": "Freeze a comparison protocol, then qualify new feature-compatible independent captures before validation.",
    }


def finish_configuration(result):
    folds = result["folds"]
    result["aggregate"] = aggregate_folds(folds)
    result["total_fit_seconds"] = sum(row["fit_seconds"] for row in folds)
    result["total_cpu_seconds"] = sum(row["cpu_seconds"] for row in folds)
    if result["config"]["feature_set"] == "full":
        drops = [row["importance"]["balanced_accuracy_drop"] for row in folds]
        ranking = sorted(drops[0], key=lambda name: (-mean(row[name] for row in drops), name))
        result["importance"] = {
            "top_features": {name: spread([row[name] for row in drops]) for name in ranking[:10]},
            "watched_fields": {name: spread([row[name] for row in drops]) for name in MONITORED_FIELDS},
        }
    result.update(status="completed", finished_at=utc_stamp())


def work(directory, manifest, smoke, state, guard):
    data, source = load_overnight_data(directory, smoke=smoke)
    guard()
    roles, audit = plan_folds(data, minimum_class_rows=30 if smoke else 500)
    audit["source"] = source
    audit["rotations_sha256"] = [{role: sha256(indices.astype("<i8").tobytes()).hexdigest()
                                  for role, indices in fold.items()} for fold in roles]
    path = directory / "split-audit.json"
    if path.exists() and read_json(path) != audit:
        raise ValueError("The recomputed split or input differs from the saved audit")
    write_atomic(path, audit)
    if audit["blockers"]:
        raise ValueError("Grouped rotations failed the gates in split-audit.json")

    for config in manifest["plan"]["configurations"]:
        guard()
        path, result = checkpoint(directory, config)
        if result["status"] in {"completed", "failed"}:
            continue
        columns = list(FEATURE_SETS[config["feature_set"]])
        features = data.predictors[:, column_positions(data.columns, config["feature_set"])]
        result.setdefault("started_at", utc_stamp())
        result["status"] = "in_progress"
        write_atomic(path, result)
        for fold, split in enumerate(roles[len(result["folds"]):], len(result["folds"]) + 1):
            guard()
            state.update(config=config["id"], fold=fold, fold_started_at=utc_stamp(),
                         peak_process_rss_bytes=peak_rss_bytes(), process_cpu_seconds=process_time())
            write_atomic(directory / "state.json", state)
            started = utc_stamp()
            try:
                row = fit_fold(config, columns, features, data.labels, split, fold, guard)
            except Halt:
                raise
            except (ValueError, RuntimeError, FloatingPointError) as error:
                result.update(status="failed", error=f"{type(error).__name__}: {error}", finished_at=utc_stamp())
                break
            result["folds"].append({**row, "started_at": started, "finished_at": utc_stamp()})
            write_atomic(path, result)
        else:
            finish_configuration(result)
        write_atomic(path, result)
        log_event(directory, "configuration_terminal", config=config["id"], status=result["status"], error=result.get("error"))
        write_atomic(directory / "report.json", report_run(directory, manifest))
    guard()


def run(directory, smoke):
    directory.mkdir(parents=True, exist_ok=True)
    with run_lock(directory):
        (directory / "configs").mkdir(exist_ok=True)
        manifest = run_manifest(directory, smoke)
        if all(checkpoint(directory, config)[1]["status"] in {"completed", "failed"}
               for config in manifest["plan"]["configurations"]):
            write_atomic(directory / "report.json", report_run(directory, manifest))
            return 0
        deadline = manifest["deadline_epoch"]
        initial_limit = limit_reason(deadline)
        if initial_limit:
            raise Halt(initial_limit)
        (directory / "stop.request").unlink(missing_ok=True)
        attempt = uuid4().hex
        state = {"worker_pid": os.getpid(), "attempt": attempt, "started_at": utc_stamp(), "status": "running"}
        write_atomic(directory / "state.json", state)
        log_event(directory, "attempt_started", attempt=attempt, worker_pid=os.getpid())
        finished = Event()
        monitor = Thread(target=watchdog, args=(directory, deadline, attempt, finished), daemon=True)
        monitor.start()

        def guard():
            if (directory / "stop.request").is_file():
                raise Halt("safe stop requested")
            if reason := limit_reason(deadline):
                raise Halt(reason)

        exit_code = 0
        try:
            with threadpool_limits(limits=NATIVE_THREADS):
                work(directory, manifest, smoke, state, guard)
            state["status"] = "finished"
        except (Halt, KeyboardInterrupt) as error:
            state.update(status="stopped", reason=str(error) or "operator interrupted")
            exit_code = 2
        except (OSError, ValueError, KeyError, TypeError, RuntimeError, MemoryError) as error:
            state.update(status="failed", reason=f"{type(error).__name__}: {error}")
            exit_code = 1
        finally:
            finished.set()
            monitor.join()
            state.update(finished_at=utc_stamp(), peak_process_rss_bytes=peak_rss_bytes(), process_cpu_seconds=process_time())
            write_atomic(directory / "state.json", state)
            log_event(directory, "attempt_terminal", attempt=attempt, status=state["status"], reason=state.get("reason"))
            write_atomic(directory / "report.json", report_run(directory, manifest))
        print(json.dumps(state))
        return exit_code


def status(directory, manifest):
    state_path = directory / "state.json"
    state = read_json(state_path) if state_path.exists() else {"status": "pending"}
    progress = [checkpoint(directory, config)[1] for config in manifest["plan"]["configurations"]]
    active = is_active(directory)
    if state["status"] == "running" and not active:
        marker = directory / f"interrupt-{state['attempt']}.json"
        state.update(status="interrupted", reason=read_json(marker)["reason"] if marker.exists() else "worker ended")
    return {**state, "active": active, "stop_requested": (directory / "stop.request").is_file(),
            "deadline_utc": utc_stamp(manifest["deadline_epoch"]), "configurations": len(progress),
            "completed": sum(item["status"] == "completed" for item in progress),
            "failed": sum(item["status"] == "failed" for item in progress),
            "finished_folds": sum(len(item["folds"]) for item in progress)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("run", "status", "report", "stop"))
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--smoke", action="store_true", help="use a separate 6,000-row smoke directory with two configurations")
    args = parser.parse_args(argv)
    directory = args.output.resolve()
    data_root = Path("data").resolve()
    if directory == data_root or not directory.is_relative_to(data_root):
        parser.error("choose a run directory inside ignored local data/")
    if args.smoke and directory == DEFAULT_OUTPUT.resolve():
        parser.error("smoke runs require their own --output directory")
    try:
        if args.command == "run":
            return run(directory, args.smoke)
        manifest = read_json(directory / "plan.json")
        if args.command == "stop":
            if is_active(directory):
                try:
                    with (directory / "stop.request").open("x", encoding="utf-8") as marker:
                        marker.write(utc_stamp())
                except FileExistsError:
                    pass
        print(json.dumps(report_run(directory, manifest) if args.command == "report" else status(directory, manifest), indent=2))
    except (OSError, ValueError, Halt) as error:
        parser.exit(1, f"G32.1 stopped: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
