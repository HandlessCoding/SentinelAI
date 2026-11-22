"""Run the staged G32.2 study with its own local checkpoints and worker controls."""

import argparse
from hashlib import sha256
from importlib.metadata import version
import json
import os
from pathlib import Path
import platform
from threading import Event, Thread
from time import process_time, time
from uuid import uuid4

from threadpoolctl import threadpool_limits

from ml.run_baseline import DEPENDENCIES
from ml.run_unsw_development import peak_rss_bytes, sha256_file
from ml.run_unsw_overnight import (Halt, MEMORY_BYTES, TIME_SECONDS, is_active, limit_reason, log_event,
                                  read_json, run_lock, utc_stamp, watchdog, write_atomic)
from ml.unsw_extended_design import (CHALLENGE_MODEL_SEED, DISCOVERY_FOLDS, DISCOVERY_SEEDS, FEATURE_SETS,
                                     LOCK_SEED, SHORTLIST_SIZE, SMOKE_FIXTURE_SEED, candidates, study_splits, synthetic_smoke_data)
from ml.unsw_extended_metrics import (DIAGNOSTIC_POLICY, EVALUATION_FLOOR, POLICIES, TARGETS, aggregate_policies,
                                      best_policy, fit_rotation, rank_metrics)
from ml.unsw_overnight_data import G32_ARCHIVE_SHA256, load_overnight_data
from ml.unsw_overnight_models import FOREST_WORKERS, NATIVE_THREADS, spread


DEFAULT_OUTPUT = Path("data/g32-2-extended")


def digest_json(document):
    return sha256(json.dumps(document, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def plan_manifest(directory, smoke):
    modules = ("run_unsw_extended", "unsw_extended_design", "unsw_extended_metrics", "run_unsw_overnight",
               "unsw_overnight_data", "unsw_overnight_models", "run_unsw_development", "run_model_comparison",
               "unsw_development_split", "run_baseline", "inspect_dataset", "inference")
    plan = {
        "study": "G32.2", "smoke": smoke, "configurations": candidates(smoke=smoke), "features": FEATURE_SETS,
        "policies": POLICIES, "calibration_recall_targets": TARGETS, "evaluation_floor": EVALUATION_FLOOR,
        "challenge_split_seed": LOCK_SEED, "challenge_model_seed": CHALLENGE_MODEL_SEED,
        "synthetic_smoke_fixture_seed": SMOKE_FIXTURE_SEED,
        "discovery_seeds": DISCOVERY_SEEDS[:2] if smoke else DISCOVERY_SEEDS,
        "folds_per_discovery_seed": 2 if smoke else DISCOVERY_FOLDS, "shortlist_size": 2 if smoke else SHORTLIST_SIZE,
        "g32_partition_archive_sha256": G32_ARCHIVE_SHA256,
        "runtime_seconds": 300 if smoke else TIME_SECONDS, "memory_bytes": MEMORY_BYTES,
        "native_threads": NATIVE_THREADS, "forest_workers": FOREST_WORKERS,
        "versions": {"python": platform.python_version(), **{package: version(package) for package in DEPENDENCIES}},
        "module_sha256": {name: sha256_file(Path(__file__).with_name(name + ".py")) for name in modules},
    }
    signature = digest_json(plan)
    path = directory / "plan.json"
    if path.is_file():
        previous = read_json(path)
        if previous["plan_sha256"] != signature or digest_json(previous["plan"]) != signature:
            raise ValueError("Resume requires the original G32.2 code, plan, runtime, and mode")
        return previous
    started = time()
    document = {"started_at": utc_stamp(started), "deadline_epoch": started + plan["runtime_seconds"],
                "plan_sha256": signature, "plan": plan}
    write_atomic(path, document)
    return document


def job_identity(stage, config, seed, policies, folds):
    return {"stage": stage, "config": config, "seed": seed, "policies": list(policies), "planned_folds": len(folds)}


def read_job(path, identity):
    if not path.is_file():
        return {"identity": identity, "status": "in_progress", "folds": [], "started_at": utc_stamp()}
    job = read_json(path)
    indices = [row["fold"] for row in job["folds"]]
    if (job["identity"] != identity or indices != list(range(1, len(indices) + 1)) or len(indices) > identity["planned_folds"]
            or (job["status"] == "completed" and len(indices) != identity["planned_folds"])):
        raise ValueError(f"Checkpoint identity or completed folds are invalid: {path.name}")
    return job


def run_job(directory, stage, config, data, folds, seed, policies, state, guard):
    path = directory / "checkpoints" / f"{stage}-{seed}-{config['id']}.json"
    identity = job_identity(stage, config, seed, policies, folds)
    job = read_job(path, identity)
    if job["status"] != "in_progress":
        return job
    marker = directory / f"challenge-started-{config['id']}.json"

    def freeze(thresholds):
        write_atomic(marker, {"identity": identity, "selection_sha256": sha256_file(directory / "selection.json"),
                              "thresholds": thresholds, "evaluation_started_at": utc_stamp()})

    if stage == "challenge" and marker.is_file() and not job["folds"]:
        job.update(status="unavailable", error="Challenge scoring may have started before interruption. It will not be repeated.")
    else:
        for index in range(len(job["folds"]), len(folds)):
            guard()
            state.update(stage=stage, config=config["id"], seed=seed, fold=index + 1, fold_started_at=utc_stamp(),
                         peak_process_rss_bytes=peak_rss_bytes(), process_cpu_seconds=process_time())
            write_atomic(directory / "state.json", state)
            write_atomic(path, job)
            try:
                row = fit_rotation(config, data, folds[index], seed, index + 1, guard, policies=policies,
                                   diagnostics=stage != "discovery", freeze=freeze if stage == "challenge" else None)
            except Halt:
                raise
            except (ValueError, RuntimeError, FloatingPointError) as error:
                job.update(status="failed", error=f"{type(error).__name__}: {error}")
                break
            job["folds"].append({**row, "started_at": state["fold_started_at"], "finished_at": utc_stamp()})
            write_atomic(path, job)
        else:
            job.update(status="completed", aggregate=aggregate_policies(job["folds"]))
    job["finished_at"] = utc_stamp()
    write_atomic(path, job)
    log_event(directory, "configuration_terminal", stage=stage, config=config["id"], seed=seed,
              status=job["status"], error=job.get("error"))
    return job


def rank_records(records):
    return sorted(records, key=lambda record: (*rank_metrics(record["metrics"]), record["config"]["id"]))


def discovery_rank(jobs):
    ranked = []
    for job in jobs:
        if job["status"] == "completed":
            policy = best_policy(job["aggregate"])
            ranked.append({"config": job["identity"]["config"], "policy": policy, "metrics": job["aggregate"][policy]})
    return rank_records(ranked)


def shortlist(ranked, size):
    chosen = {}
    for family in ("hgb", "rf", "lr"):
        for feature_set in FEATURE_SETS:
            match = next((row for row in ranked if row["config"]["family"] == family
                          and row["config"]["feature_set"] == feature_set), None)
            if match is not None:
                chosen[match["config"]["id"]] = match
    for record in ranked:
        if len(chosen) >= size:
            break
        chosen.setdefault(record["config"]["id"], record)
    return rank_records(chosen.values())[:size]


def seeded_ranking(promoted, discovery_jobs, replicated, seeds):
    original = {job["identity"]["config"]["id"]: job for job in discovery_jobs}
    by_replicate = {(job["identity"]["config"]["id"], job["identity"]["seed"]): job for job in replicated}
    result = []
    for record in promoted:
        name, policy = record["config"]["id"], record["policy"]
        jobs = [original[name], *(by_replicate[name, seed] for seed in seeds)]
        if not all(job["status"] == "completed" for job in jobs):
            continue
        # Discovery checkpoints contain all policies. Keep the frozen one for cross-seed aggregation.
        rows = [{"policies": {policy: fold["policies"][policy]}} for job in jobs for fold in job["folds"]]
        result.append({**record, "metrics": aggregate_policies(rows)[policy], "by_seed": {
            str(job["identity"]["seed"]): job["aggregate"][policy] for job in jobs
        }})
    return rank_records(result)


def freeze_document(path, document):
    if path.is_file():
        if read_json(path) != document:
            raise ValueError(f"The recomputed study decision differs from {path.name}")
    else:
        write_atomic(path, document)


def execute_plan(directory, manifest, state, guard):
    plan = manifest["plan"]
    if plan["smoke"]:
        data, source = synthetic_smoke_data(), {"synthetic": True, "seed": SMOKE_FIXTURE_SEED}
    else:
        data, source = load_overnight_data(directory)
    guard()
    discovery, rotations, challenge, audit = study_splits(data, smoke=plan["smoke"])
    freeze_document(directory / "split-audit.json", {"source": source, **audit})

    first, *replicates = plan["discovery_seeds"]
    count = plan["folds_per_discovery_seed"]
    fold_jobs = []
    for config in plan["configurations"]:
        guard()
        fold_jobs.append(run_job(directory, "discovery", config, discovery, rotations[first][:count],
                                 first, POLICIES, state, guard))
    ranking = discovery_rank(fold_jobs)
    if not ranking:
        raise ValueError("No discovery configuration completed. The challenge remains sealed.")
    promoted = shortlist(ranking, plan["shortlist_size"])
    freeze_document(directory / "promotion.json", {"shortlist": promoted, "phase": "discovery-only"})
    repeat_jobs = []
    for seed in replicates:
        for chosen in promoted:
            guard()
            repeat_jobs.append(run_job(directory, "replicate", chosen["config"], discovery, rotations[seed][:count],
                                       seed, (chosen["policy"],), state, guard))
    ranking = seeded_ranking(promoted, fold_jobs, repeat_jobs, replicates)
    if not ranking:
        raise ValueError("No shortlisted configuration completed all stability repeats. The challenge remains sealed.")
    primary = ranking[0]
    lineup = {primary["config"]["id"]: primary}
    for feature_set in ("full", "no_ttl"):
        comparator = next((row for row in ranking if row["config"]["feature_set"] == feature_set), None)
        if comparator is not None:
            lineup.setdefault(comparator["config"]["id"], comparator)
    freeze_document(directory / "selection.json", {"primary": primary["config"]["id"],
        "primary_held_floor_every_discovery_fold": primary["metrics"]["recall"]["min"] >= EVALUATION_FLOOR,
        "discovery_seed_rank": ranking, "locked_challenge_lineup": list(lineup.values()),
        "selection_scope": "initial discovery and seed replicates only"})
    for chosen in lineup.values():
        guard()
        run_job(directory, "challenge", chosen["config"], data, [challenge], CHALLENGE_MODEL_SEED,
                (chosen["policy"],), state, guard)


def read_jobs(directory):
    return [read_json(path) for path in sorted((directory / "checkpoints").glob("*.json"))]


def status(directory, manifest, jobs):
    path = directory / "state.json"
    snapshot = read_json(path) if path.is_file() else {"status": "pending"}
    active = is_active(directory)
    if snapshot["status"] == "running" and not active:
        marker = directory / f"interrupt-{snapshot['attempt']}.json"
        snapshot.update(status="interrupted", reason=read_json(marker)["reason"] if marker.is_file() else "worker exited")
    return {**snapshot, "active": active, "deadline_utc": utc_stamp(manifest["deadline_epoch"]),
            "stop_requested": (directory / "stop.request").is_file(),
            "planned_discovery_configurations": len(manifest["plan"]["configurations"]),
            "completed_by_stage": {stage: sum(job["status"] == "completed" and job["identity"]["stage"] == stage for job in jobs)
                                   for stage in ("discovery", "replicate", "challenge")},
            "failed_or_unavailable": sum(job["status"] in {"failed", "unavailable"} for job in jobs),
            "saved_folds": sum(len(job["folds"]) for job in jobs)}


def report(directory, manifest, jobs, snapshot):
    discovery = [job for job in jobs if job["identity"]["stage"] == "discovery"]
    complete = [job for job in discovery if job["status"] == "completed"]
    grouped = {}
    for job in complete:
        config = job["identity"]["config"]
        grouped.setdefault(config["recipe"], {})[config["feature_set"]] = job
    ablations = []
    for recipe, variants in grouped.items():
        if "full" not in variants or len(variants) < 2:
            continue
        reference = variants["full"]["folds"]
        ablations.append({"recipe": recipe, "policy": DIAGNOSTIC_POLICY, "delta_from_full": {
            name: {metric: spread([left["policies"][DIAGNOSTIC_POLICY]["metrics"][metric]
                                   - right["policies"][DIAGNOSTIC_POLICY]["metrics"][metric]
                                   for left, right in zip(job["folds"], reference, strict=True)])
                   for metric in ("recall", "false_positive_rate")}
            for name, job in variants.items() if name != "full"
        }})
    selection = directory / "selection.json"
    attempted = {job["identity"]["config"]["id"] for job in discovery}
    return {"status": snapshot, "plan_sha256": manifest["plan_sha256"], "discovery_ranking": discovery_rank(discovery),
            "selection": read_json(selection) if selection.is_file() else None, "paired_ablations": ablations,
            "jobs": jobs, "discovery_not_started": [item["id"] for item in manifest["plan"]["configurations"]
                                                     if item["id"] not in attempted],
            "interrupts": [read_json(path) for path in sorted(directory.glob("interrupt-*.json"))],
            "interpretation": "Exploratory. The internal challenge is locked only for G32.2. Underlying fitting rows were studied in G32.1. Repeated seeds reuse discovery evidence.",
            "g33": "Prespecify candidates and decision policies before qualifying new independent, feature-compatible, reviewed captures."}


def run(directory, smoke):
    directory.mkdir(parents=True, exist_ok=True)
    with run_lock(directory):
        (directory / "checkpoints").mkdir(exist_ok=True)
        manifest = plan_manifest(directory, smoke)
        state_path = directory / "state.json"
        if state_path.is_file() and read_json(state_path)["status"] == "finished":
            return 0
        if reason := limit_reason(manifest["deadline_epoch"]):
            raise Halt(reason)
        deadline = manifest["deadline_epoch"]
        (directory / "stop.request").unlink(missing_ok=True)
        attempt = uuid4().hex
        state = {"worker_pid": os.getpid(), "attempt": attempt, "started_at": utc_stamp(), "status": "running"}
        write_atomic(state_path, state)
        log_event(directory, "attempt_started", attempt=attempt, worker_pid=os.getpid())
        finished = Event()
        monitor = Thread(target=watchdog, args=(directory, deadline, attempt, finished), daemon=True)
        monitor.start()

        def guard():
            if (directory / "stop.request").is_file():
                raise Halt("safe stop requested")
            if reason := limit_reason(deadline):
                raise Halt(reason)

        result = 0
        try:
            with threadpool_limits(limits=NATIVE_THREADS):
                execute_plan(directory, manifest, state, guard)
            state["status"] = "finished"
        except (Halt, KeyboardInterrupt) as error:
            state.update(status="stopped", reason=str(error) or "operator interrupted")
            result = 2
        except (OSError, ValueError, KeyError, TypeError, RuntimeError, MemoryError) as error:
            state.update(status="failed", reason=f"{type(error).__name__}: {error}")
            result = 1
        finally:
            finished.set()
            monitor.join()
            state.update(finished_at=utc_stamp(), peak_process_rss_bytes=peak_rss_bytes(), process_cpu_seconds=process_time())
            write_atomic(state_path, state)
            log_event(directory, "attempt_terminal", attempt=attempt, status=state["status"], reason=state.get("reason"))
            write_atomic(directory / "report.json", report(directory, manifest, read_jobs(directory), state))
        print(json.dumps(state))
        return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("run", "status", "report", "stop"))
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--smoke", action="store_true", help="use a separate smoke directory and three candidates")
    args = parser.parse_args(argv)
    directory, data_root = args.output.resolve(), Path("data").resolve()
    if directory == data_root or not directory.is_relative_to(data_root):
        parser.error("choose a run directory inside ignored local data/")
    if args.smoke and directory == DEFAULT_OUTPUT.resolve():
        parser.error("smoke runs require a separate --output directory")
    try:
        if args.command == "run":
            return run(directory, args.smoke)
        manifest = read_json(directory / "plan.json")
        if args.command == "stop" and is_active(directory):
            try:
                with (directory / "stop.request").open("x", encoding="utf-8") as marker:
                    marker.write(utc_stamp())
            except FileExistsError:
                pass
        jobs = read_jobs(directory)
        snapshot = status(directory, manifest, jobs)
        print(json.dumps(report(directory, manifest, jobs, snapshot) if args.command == "report" else snapshot, indent=2))
    except (OSError, ValueError, Halt) as error:
        parser.exit(1, f"G32.2 stopped: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
