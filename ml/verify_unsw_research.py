"""Verify saved G32.1 and G32.2 evidence without evaluating any held-out rows."""

from collections import Counter
from datetime import datetime
from math import isclose
from pathlib import Path

from ml.run_unsw_development import TRAINING_SHA256, sha256_file
from ml.run_unsw_extended import digest_json, discovery_rank, read_jobs, seeded_ranking, shortlist
from ml.run_unsw_overnight import checkpoint, read_json, report_run
from ml.unsw_extended_design import CHALLENGE_MODEL_SEED, DISCOVERY_SEEDS, candidates
from ml.unsw_extended_metrics import POLICIES, TARGETS, aggregate_policies
from ml.unsw_overnight_data import FIT_CLASSES, FIT_ROWS, G32_ARCHIVE_SHA256


G321_ROOT = Path("data/g32-1-overnight")
G322_ROOT = Path("data/g32-2-extended")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def verify_matrix(matrix, counts):
    require(len(matrix) == 2 and all(len(row) == 2 for row in matrix), "Invalid confusion matrix shape")
    require(all(type(cell) is int and cell >= 0 for row in matrix for cell in row), "Invalid confusion matrix count")
    (tn, fp), (fn, tp) = matrix
    require(tn + fp == counts["normal"] and fn + tp == counts["attack"], "Confusion totals differ from class coverage")
    return tn, fp, fn, tp


def verify_metrics(metrics, counts):
    tn, fp, fn, tp = verify_matrix(metrics["confusion_matrix"], counts)
    recall = tp / (fn + tp)
    fpr = fp / (tn + fp)
    expected = {"recall": recall, "false_positive_rate": fpr, "accuracy": (tn + tp) / (tn + fp + fn + tp),
                "precision": tp / (tp + fp) if tp + fp else 0, "balanced_accuracy": (1 - fpr + recall) / 2,
                "f1": 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else 0}
    require(all(isclose(metrics[name], value, rel_tol=1e-12, abs_tol=1e-12) for name, value in expected.items()),
            "Recorded metrics do not match the confusion matrix")


def verify_overnight(root):
    manifest = read_json(root / "plan.json")
    config = manifest["plan"]["configurations"]
    jobs = [checkpoint(root, item)[1] for item in config]
    summary = report_run(root, manifest)
    audit = read_json(root / "split-audit.json")
    compare_source(root, audit)
    require(not manifest["plan"]["smoke"] and not audit["blockers"] and len(audit["folds"]) == 5
            and all(not any(pair.values()) for fold in audit["folds"] for pair in fold["pairwise_group_overlap"].values()),
            "G32.1 must have five eligible group-separated rotations")
    require(digest_json(manifest["plan"]) == manifest["plan_sha256"], "G32.1 frozen plan digest mismatch")
    require(len(jobs) == 27 and all(job["status"] == "completed" and len(job["folds"]) == 5 for job in jobs),
            "G32.1 requires 27 complete five-fold configurations")
    require(read_json(root / "state.json")["status"] == "finished" and read_json(root / "report.json") == summary,
            "G32.1 report does not match its checkpoints")
    for job in jobs:
        for fold in job["folds"]:
            for policy in ("default", "calibrated"):
                verify_metrics(fold[policy], fold["class_counts"]["evaluation"])
            verify_metrics(fold["calibration"], fold["class_counts"]["calibration"])
    return {"configurations": 27, "folds": 135, "plan_sha256": manifest["plan_sha256"]}


def compare_source(root, audit):
    source = audit["source"]
    require(source["g32_partition_archive_sha256"] == G32_ARCHIVE_SHA256 and source["source_csv_sha256"] == TRAINING_SHA256
            and source["used_rows"] == FIT_ROWS and source["class_counts"] == FIT_CLASSES,
            "Unexpected G32.2 fitting-only source")
    require(sha256_file(root / "fit-only.csv") == source["fitting_snapshot_sha256"], "Fitting-only snapshot checksum mismatch")


def verify_job(job, expected_folds, audits):
    identity = job["identity"]
    folds = job["folds"]
    require(job["status"] == "completed" and identity["planned_folds"] == expected_folds
            and [row["fold"] for row in folds] == list(range(1, expected_folds + 1)), "Incomplete G32.2 checkpoint")
    for row, audit in zip(folds, audits, strict=True):
        require(row["seed"] == identity["seed"] and set(row["policies"]) == set(identity["policies"])
                and row["class_counts"] == audit["class_counts"], "Fold metadata differs from the declared protocol")
        for policy, result in row["policies"].items():
            verify_metrics(result["metrics"], row["class_counts"]["evaluation"])
            _, _, fn, tp = verify_matrix(result["threshold_confusion"], row["class_counts"]["threshold"])
            method, target = policy.split("-")
            require(result["method"] == method and result["target"] == TARGETS.get(target) and 0 <= result["threshold"] <= 1,
                    "Threshold metadata differs from its policy")
            require(target == "default" or tp / (fn + tp) >= TARGETS[target], "Calibration recall floor did not hold")
    require(aggregate_policies(folds) == job["aggregate"], "Fold rollup differs from the recorded aggregate")


def verify_extended(root):
    manifest = read_json(root / "plan.json")
    plan = manifest["plan"]
    require(digest_json(plan) == manifest["plan_sha256"] and plan["study"] == "G32.2" and not plan["smoke"],
            "G32.2 frozen plan digest or mode mismatch")
    require(plan["configurations"] == candidates() and plan["discovery_seeds"] == list(DISCOVERY_SEEDS),
            "The recorded candidate plan differs from the approved runner")
    for module, expected in plan["module_sha256"].items():
        require(sha256_file(Path(__file__).with_name(module + ".py")) == expected, f"Original runner module changed: {module}")
    audit = read_json(root / "split-audit.json")
    compare_source(root, audit)
    boundaries = [audit["challenge"], *(fold for folds in audit["rotations"].values() for fold in folds)]
    require(len(boundaries) == 16 and all(not any(pair.values()) for item in boundaries for pair in item["overlapping_groups"].values()),
            "The recorded split contains predictor overlap")
    jobs = read_jobs(root)
    report = read_json(root / "report.json")
    selection = read_json(root / "selection.json")
    require(report["status"] == read_json(root / "state.json") and report["status"]["status"] == "finished"
            and report["jobs"] == jobs and report["selection"] == selection
            and report["plan_sha256"] == manifest["plan_sha256"], "G32.2 report differs from its saved checkpoints")
    keys = [(j["identity"]["stage"], j["identity"]["seed"], j["identity"]["config"]["id"]) for j in jobs]
    require(len(keys) == len(set(keys)), "Duplicate checkpoint identity")
    stage_counts = Counter(stage for stage, _, _ in keys)
    require(stage_counts == {"discovery": 184, "replicate": 24, "challenge": 2}, "Unexpected G32.2 stage counts")
    grouped = {stage: [job for job in jobs if job["identity"]["stage"] == stage] for stage in stage_counts}
    promoted = shortlist(discovery_rank(grouped["discovery"]), 12)
    require(promoted == read_json(root / "promotion.json")["shortlist"], "Shortlist differs from the prespecified selection")
    ranking = seeded_ranking(promoted, grouped["discovery"], grouped["replicate"], DISCOVERY_SEEDS[1:])
    require(ranking == selection["discovery_seed_rank"] and ranking[0]["config"]["id"] == selection["primary"],
            "The recorded primary differs from discovery-only selection")
    lineup = {ranking[0]["config"]["id"]: ranking[0]}
    for features in ("full", "no_ttl"):
        comparator = next((row for row in ranking if row["config"]["feature_set"] == features), None)
        if comparator is not None:
            lineup.setdefault(comparator["config"]["id"], comparator)
    require(list(lineup.values()) == selection["locked_challenge_lineup"], "The challenge lineup differs from the recorded discovery ranking")
    expected_keys = {("discovery", DISCOVERY_SEEDS[0], item["id"]): (item, list(POLICIES)) for item in candidates()}
    expected_keys.update({("replicate", seed, item["config"]["id"]): (item["config"], [item["policy"]])
                          for seed in DISCOVERY_SEEDS[1:] for item in promoted})
    expected_keys.update({("challenge", CHALLENGE_MODEL_SEED, item["config"]["id"]): (item["config"], [item["policy"]])
                          for item in selection["locked_challenge_lineup"]})
    require(set(keys) == expected_keys.keys(), "Missing or unexpected stage/seed/candidate checkpoints")
    selection_sha = sha256_file(root / "selection.json")
    for key, job in zip(keys, jobs, strict=True):
        stage, seed, name = key
        config, policies = expected_keys[key]
        require(job["identity"]["config"] == config and job["identity"]["policies"] == policies,
                "Checkpoint configuration differs from its frozen stage")
        if stage == "challenge":
            verify_job(job, 1, [audit["challenge"]])
            marker = read_json(root / f"challenge-started-{name}.json")
            decisions = {policy: {key: value for key, value in result.items() if key != "metrics"}
                         for policy, result in job["folds"][0]["policies"].items()}
            require(marker["identity"] == job["identity"] and marker["selection_sha256"] == selection_sha
                    and marker["thresholds"] == decisions, "Challenge start marker differs from the frozen outcome")
            require(datetime.fromisoformat(marker["evaluation_started_at"]) <= datetime.fromisoformat(job["folds"][0]["finished_at"]),
                    "Challenge marker postdates the evaluation record")
        else:
            verify_job(job, 5, audit["rotations"][str(seed)])
    return {"stages": dict(stage_counts), "folds": sum(len(job["folds"]) for job in jobs),
            "plan_sha256": manifest["plan_sha256"], "selection_sha256": selection_sha}, grouped, selection, audit
