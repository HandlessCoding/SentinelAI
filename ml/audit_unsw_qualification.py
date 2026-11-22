"""Audit saved evidence and optionally replay one discovery seed for two frozen recipes."""

import argparse
import csv
import json
from pathlib import Path
from time import perf_counter

import numpy as np
from sklearn.metrics import brier_score_loss
from threadpoolctl import threadpool_limits

from ml.run_baseline import class_distribution, load_training
from ml.run_unsw_development import sha256_file, write_report
from ml.unsw_development_split import normalize_predictors
from ml.unsw_extended_design import DISCOVERY_SEEDS, FEATURE_SETS, feature_groups, positions, study_splits
from ml.unsw_extended_metrics import classify, confusion, fit_probability_map
from ml.unsw_overnight_data import FIT_CLASSES
from ml.unsw_overnight_models import NATIVE_THREADS, make_pipeline
from ml.verify_unsw_research import G321_ROOT, G322_ROOT, require, verify_extended, verify_overnight


OUTCOMES = {"tn": (0, False), "fp": (0, True), "fn": (1, False), "tp": (1, True)}
RANGE_FIELDS = ("dur", "rate", "sttl", "dttl", "swin", "dwin", "sbytes", "dbytes", "dmean",
                "ct_srv_dst", "ct_dst_src_ltm", "ct_state_ttl")


def summary_quantiles(values):
    return dict(zip(("p05", "median", "p95"), np.quantile(values, (0.05, 0.5, 0.95)).tolist())) if len(values) else None


def reliability(labels, scores):
    require(len(labels) > 0 and np.isfinite(scores).all() and np.all((0 <= scores) & (scores <= 1)),
            "Invalid calibration diagnostic inputs")
    bins = []
    index = np.minimum((scores * 10).astype(int), 9)
    for i in range(10):
        mask = index == i
        if mask.any():
            bins.append({"lower": i / 10, "upper": (i + 1) / 10, "rows": int(mask.sum()),
                         "mean_score": float(scores[mask].mean()), "observed_attack_share": float(labels[mask].mean())})
    return {"brier": float(brier_score_loss(labels, scores)), "bins": bins, "ece_10_equal_width": sum(
        row["rows"] * abs(row["mean_score"] - row["observed_attack_share"]) for row in bins
    ) / len(labels)}


def discovery_categories(path, indices, labels):
    categories = []
    with path.open(encoding="utf-8-sig", newline="") as stream:
        rows = csv.reader(stream, strict=True)
        header = next(rows)
        category, label = header.index("attack_cat"), header.index("label")
        for i, row in enumerate(rows):
            selected = len(categories)
            if selected == len(indices):
                break
            if i == indices[selected]:
                require(int(row[label]) == labels[selected], "Replay category labels do not match the discovery rows")
                categories.append(row[category].strip() or "(unavailable)")
    require(len(categories) == len(indices), "Category alignment is incomplete")
    return np.asarray(categories)


def feature_group_errors(labels, predicted, keys):
    unique, inverse = np.unique(keys, return_inverse=True)
    normal = np.bincount(inverse[labels == 0], minlength=len(unique))
    attack = np.bincount(inverse[labels == 1], minlength=len(unique))
    conflicting = (normal > 0) & (attack > 0)
    repeated = normal + attack > 1
    kinds = {"singleton": ~repeated, "repeated_single_label": repeated & ~conflicting, "conflicting": conflicting}
    return {kind: {"groups": int(mask.sum()), "confusion_matrix": confusion(labels[mask[inverse]], predicted[mask[inverse]]),
                   "minimum_errors_from_exact_conflicts": int(np.minimum(normal[mask], attack[mask]).sum())}
            for kind, mask in kinds.items()}


def category_errors(labels, predicted, categories, roles):
    output = {}
    for name in np.unique(categories[labels == 1]):
        mask = (categories == name) & (labels == 1)
        by_fold = [{"attack": int(mask[fold["evaluation"]].sum()),
                    "missed": int((mask & ~predicted)[fold["evaluation"]].sum())} for fold in roles]
        count, missed = int(mask.sum()), int((mask & ~predicted).sum())
        output[name] = {"attack": count, "missed": missed, "recall": 1 - missed / count,
                        "folds_with_misses": sum(row["missed"] > 0 for row in by_fold), "folds": by_fold}
    return output


def warm_latency(model, transform, predictors):
    results = {}
    for size, repetitions in ((1, 40), (100, 25)):
        batch = predictors[:size]
        transform(model.predict_proba(batch)[:, 1])
        durations = []
        for _ in range(repetitions):
            start = perf_counter()
            transform(model.predict_proba(batch)[:, 1])
            durations.append((perf_counter() - start) * 1000)
        results[str(size)] = {"repetitions": repetitions, "median_ms": float(np.median(durations)),
                              "p95_ms": float(np.quantile(durations, 0.95))}
    return results


def replay_candidate(discovery, roles, categories, feature_keys, checkpoint, policy):
    identity = checkpoint["identity"]
    require(identity["stage"] == "discovery" and identity["seed"] == DISCOVERY_SEEDS[0],
            "Qualification replay accepts only the original discovery seed")
    config, seed = identity["config"], identity["seed"]
    columns = list(FEATURE_SETS[config["feature_set"]])
    inputs = discovery.predictors[:, positions(discovery.columns, columns)]
    labels = discovery.labels
    raw, calibrated = np.full(len(labels), np.nan), np.full(len(labels), np.nan)
    predicted = np.zeros(len(labels), dtype=bool)
    for index, (split, recorded) in enumerate(zip(roles, checkpoint["folds"], strict=True)):
        fitting, probability, evaluation = (split[role] for role in ("fit", "probability", "evaluation"))
        params = {**config["parameters"], "random_state": seed}
        if isinstance(params.get("class_weight"), dict):
            params["class_weight"] = {int(label): value for label, value in params["class_weight"].items()}
        model = make_pipeline({**config, "parameters": params}, columns)
        model.fit(inputs[fitting], labels[fitting])
        frozen = recorded["policies"][policy]
        transform = fit_probability_map(frozen["method"], model.predict_proba(inputs[probability])[:, 1], labels[probability])
        require(np.isnan(raw[evaluation]).all(), "Discovery row replayed twice")
        raw[evaluation] = model.predict_proba(inputs[evaluation])[:, 1]
        calibrated[evaluation] = transform(raw[evaluation])
        predicted[evaluation] = classify(calibrated[evaluation], policy, frozen["threshold"])
        require(confusion(labels[evaluation], predicted[evaluation]) == frozen["metrics"]["confusion_matrix"],
                f"Frozen discovery confusion matrix differs for {config['id']} fold {index + 1}")
        require(np.isclose(brier_score_loss(labels[evaluation], calibrated[evaluation]),
                           recorded["probability_quality"][frozen["method"]]["brier"], rtol=1e-11, atol=1e-12),
                f"Frozen discovery probability quality differs for {config['id']} fold {index + 1}")
        if index == 0:
            latency = warm_latency(model, transform, inputs[evaluation])
    require(np.isfinite(raw).all() and np.isfinite(calibrated).all(), "Discovery replay coverage is incomplete")
    masks = {name: (labels == label) & (predicted == prediction) for name, (label, prediction) in OUTCOMES.items()}
    return {
        "candidate": config["id"], "policy": policy, "seed": seed, "rows": len(labels),
        "confusion_matrix": confusion(labels, predicted),
        "confidence_by_outcome": {name: summary_quantiles(calibrated[mask]) for name, mask in masks.items()},
        "reliability": {"raw": reliability(labels, raw), "calibrated": reliability(labels, calibrated)},
        "ranges_by_outcome": {field: {name: summary_quantiles(discovery.predictors[mask, discovery.columns.index(field)].astype(float))
                                       for name, mask in masks.items()} for field in RANGE_FIELDS},
        "exact_vector_errors": feature_group_errors(labels, predicted, feature_keys),
        "attack_categories": category_errors(labels, predicted, categories, roles),
        "warm_pipeline_and_calibrator_latency_ms": latency,
    }


def audit_replay(root, jobs, selection, frozen_audit):
    source = root / "fit-only.csv"
    require(sha256_file(source) == frozen_audit["source"]["fitting_snapshot_sha256"], "Prepared snapshot is not the verified fit-only CSV")
    raw = load_training(source)
    require(class_distribution(raw.labels) == FIT_CLASSES, "Unexpected fitting class coverage")
    data = normalize_predictors(raw)
    discovery, rotations, challenge, audit = study_splits(data)
    require(audit == {key: value for key, value in frozen_audit.items() if key != "source"},
            "Recomputed group roles differ from the frozen G32.2 audit")
    indices = np.sort(np.concatenate([rows for role, rows in challenge.items() if role != "evaluation"]))
    require(not np.intersect1d(indices, challenge["evaluation"]).size, "Challenge rows leaked into discovery")
    category = discovery_categories(source, indices, discovery.labels)
    keys, _ = feature_groups(discovery)
    by_id = {job["identity"]["config"]["id"]: job for job in jobs["discovery"]}
    with threadpool_limits(NATIVE_THREADS):
        return [replay_candidate(discovery, rotations[DISCOVERY_SEEDS[0]], category, keys[item["config"]["feature_set"]],
                                 by_id[item["config"]["id"]], item["policy"]) for item in selection["locked_challenge_lineup"]]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--replay-discovery", action="store_true", help="reconstruct frozen discovery fits without selecting thresholds or scoring challenge rows")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    if args.output and not args.output.resolve().is_relative_to(Path("data").resolve()):
        parser.error("write audit output only inside ignored data/")
    try:
        g321 = verify_overnight(G321_ROOT)
        verified, jobs, selection, frozen_audit = verify_extended(G322_ROOT)
        report = {"g32_1": g321, "g32_2": verified, "primary": selection["primary"],
                  "locked_challenge": jobs["challenge"], "discovery_seed_rank": selection["discovery_seed_rank"]}
        if args.replay_discovery:
            report["discovery_replay"] = audit_replay(G322_ROOT, jobs, selection, frozen_audit)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            write_report(args.output, report)
        else:
            print(json.dumps(report, indent=2, allow_nan=False))
    except (OSError, KeyError, TypeError, ValueError) as error:
        parser.exit(1, f"Qualification audit stopped: {error}\n")


if __name__ == "__main__":
    main()
