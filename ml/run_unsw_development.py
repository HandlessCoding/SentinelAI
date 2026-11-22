"""Compare bounded candidates on a locked four-way UNSW training-data split."""

import argparse
from hashlib import file_digest, sha256
from importlib.metadata import version
import json
from pathlib import Path
import pickle
import platform
import sys
from time import perf_counter, process_time
import warnings

import numpy as np
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.inspection import permutation_importance
from sklearn.metrics import balanced_accuracy_score, roc_curve
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OrdinalEncoder
from threadpoolctl import threadpool_limits

from ml.inference import FEATURE_TYPES
from ml.run_baseline import (
    CATEGORICAL_COLUMNS, DEPENDENCIES, RANDOM_SEED, TRAINING_CSV,
    binary_metrics, class_distribution, load_training,
)
from ml.run_model_comparison import comparison_pipelines, default_metrics
from ml.unsw_development_split import audit_partitions, development_partitions, normalize_predictors


TRAINING_SHA256 = "bec7dd5ec88dc2a0ccc7a07879d338395ed7421750f675fd0339e07dfe0648fa"
RECALL_FLOOR = 0.95
IMPORTANCE_SEED = 32043
IMPORTANCE_ROWS = 1_024
IMPORTANCE_REPEATS = 2
THREADS = 1
BOOSTED = "histogram_gradient_boosting"


def sha256_file(path):
    with path.open("rb") as stream:
        return file_digest(stream, "sha256").hexdigest()


def load_pinned_training(path):
    if path.name != TRAINING_CSV.name or sha256_file(path) != TRAINING_SHA256:
        raise ValueError("Use the pinned official UNSW-NB15 training CSV")
    raw = load_training(path)
    if raw.columns != list(FEATURE_TYPES) or sha256_file(path) != TRAINING_SHA256:
        raise ValueError("The verified training input or predictor schema changed")
    return normalize_predictors(raw), raw.groups


def candidate_pipelines(columns):
    pipelines = comparison_pipelines(columns)
    categorical = [columns.index(name) for name in CATEGORICAL_COLUMNS]
    numerical = [i for i in range(len(columns)) if i not in categorical]
    preprocessor = ColumnTransformer([
        ("categorical", OrdinalEncoder(handle_unknown="use_encoded_value", unknown_value=np.nan), categorical),
        ("numeric", "passthrough", numerical),
    ])
    classifier = HistGradientBoostingClassifier(
        max_iter=100, learning_rate=0.1, max_leaf_nodes=31, min_samples_leaf=20,
        l2_regularization=1.0, early_stopping=False, random_state=RANDOM_SEED,
        categorical_features=list(range(len(categorical))),
    )
    pipelines[BOOSTED] = Pipeline([("preprocessor", preprocessor), ("classifier", classifier)])
    return pipelines


def select_recall_threshold(labels, scores):
    """Minimize calibration FPR under the recall floor, using inclusive ties."""
    if set(np.unique(labels)) != {0, 1} or not np.isfinite(scores).all():
        raise ValueError("Threshold selection requires both classes and finite scores")
    fpr, recall, thresholds = roc_curve(labels, scores, drop_intermediate=False)
    eligible = np.flatnonzero(np.isfinite(thresholds) & (recall >= RECALL_FLOOR))
    if not len(eligible):
        raise ValueError("No finite calibration threshold met the prespecified recall floor")
    index = min(eligible, key=lambda i: (fpr[i], -recall[i], -thresholds[i]))
    return float(thresholds[index])


def select_candidate(reports):
    """Rank frozen operating points on the comparison partition alone."""
    metrics = {name: item["comparison"]["calibrated"] for name, item in reports.items()}
    eligible = [name for name, result in metrics.items() if result["recall"] >= RECALL_FLOOR]
    if eligible:
        return min(eligible, key=lambda name: (metrics[name]["false_positive_rate"], -metrics[name]["recall"], name)), True
    return min(metrics, key=lambda name: (-metrics[name]["recall"], metrics[name]["false_positive_rate"], name)), False


def score_report(labels, scores, threshold):
    if not np.isfinite(scores).all() or np.any((scores < 0) | (scores > 1)):
        raise ValueError("Candidate produced invalid attack scores")
    quantiles = [0, 0.05, 0.25, 0.5, 0.75, 0.95, 1]
    return {
        "class_counts": class_distribution(labels),
        "default": default_metrics(labels, scores),
        "calibrated": binary_metrics(labels, scores >= threshold),
        "score_distribution": {"quantiles": quantiles, "normal": np.quantile(scores[labels == 0], quantiles).tolist(),
                               "attack": np.quantile(scores[labels == 1], quantiles).tolist()},
    }


def feature_importance(pipeline, columns, comparison, threshold):
    predictors, labels = comparison
    indices = np.random.default_rng(IMPORTANCE_SEED).choice(len(labels), min(len(labels), IMPORTANCE_ROWS), replace=False)

    def score(estimator, x, y):
        return balanced_accuracy_score(y, estimator.predict_proba(x)[:, 1] >= threshold)

    result = permutation_importance(
        pipeline, predictors[indices], labels[indices], scoring=score,
        random_state=IMPORTANCE_SEED, n_repeats=IMPORTANCE_REPEATS, n_jobs=1,
    )
    order = np.argsort(-result.importances_mean, kind="stable")
    return {"rows": len(indices), "class_counts": class_distribution(labels[indices]), "features": [
        {"name": columns[i], "mean_balanced_accuracy_drop": float(result.importances_mean[i]),
         "std": float(result.importances_std[i])} for i in order
    ]}


def train_candidates(columns, fit, calibration, comparison):
    """Candidate fitting and selection have no final-validation input."""
    reports, pipelines = {}, candidate_pipelines(columns)
    for name, pipeline in pipelines.items():
        print(f"Fitting {name} on {len(fit[1]):,} rows", file=sys.stderr, flush=True)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            started, cpu_started = perf_counter(), process_time()
            pipeline.fit(*fit)
            fit_seconds, fit_cpu_seconds = perf_counter() - started, process_time() - cpu_started
        started = perf_counter()
        calibration_scores = pipeline.predict_proba(calibration[0])[:, 1]
        comparison_scores = pipeline.predict_proba(comparison[0])[:, 1]
        score_seconds = perf_counter() - started
        threshold = select_recall_threshold(calibration[1], calibration_scores)
        started = perf_counter()
        importance = feature_importance(pipeline, columns, comparison, threshold)
        reports[name] = {
            "classifier_parameters": pipeline.named_steps["classifier"].get_params(deep=False),
            "preprocessing": ("ordinal categories, unknown as missing, numeric passthrough" if name == BOOSTED
                              else "one-hot categories, ignore unknown, standardize numeric predictors"),
            "threshold": threshold,
            "calibration": score_report(calibration[1], calibration_scores, threshold),
            "comparison": score_report(comparison[1], comparison_scores, threshold),
            "comparison_permutation_importance": importance,
            "fit_seconds": fit_seconds, "fit_cpu_seconds": fit_cpu_seconds, "score_seconds": score_seconds,
            "importance_seconds": perf_counter() - started,
            "pipeline_bytes": len(pickle.dumps(pipeline, protocol=pickle.HIGHEST_PROTOCOL)),
            "warnings": [f"{item.category.__name__}: {item.message}" for item in caught],
        }
    winner, met_floor = select_candidate(reports)
    return pipelines[winner], {"selected": winner, "comparison_recall_floor_met": met_floor, "candidates": reports}


def write_report(path, obj):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(obj, stream, indent=2, allow_nan=False)
        stream.write("\n")


def evaluate_frozen(directory, pipeline, threshold, final):
    """Create the one-time start marker before calculating held-aside scores."""
    write_report(directory / "final-started.json", {"selection_sha256": sha256_file(directory / "selection.json")})
    return score_report(final[1], pipeline.predict_proba(final[0])[:, 1], threshold)


def peak_rss_bytes():
    """Capture peak process resident memory on the supported development hosts."""
    if sys.platform != "win32":
        import resource

        peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return peak if sys.platform == "darwin" else peak * 1024

    import ctypes
    from ctypes import wintypes

    class MemoryCounters(ctypes.Structure):
        _fields_ = [("size", wintypes.DWORD), ("page_faults", wintypes.DWORD), *(
            (field, ctypes.c_size_t) for field in (
                "peak_working_set", "working_set", "peak_paged_pool", "paged_pool",
                "peak_nonpaged_pool", "nonpaged_pool", "pagefile", "peak_pagefile",
            )
        )]

    kernel = ctypes.WinDLL("kernel32")
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    get_memory = ctypes.WinDLL("psapi").GetProcessMemoryInfo
    get_memory.argtypes = [wintypes.HANDLE, ctypes.POINTER(MemoryCounters), wintypes.DWORD]
    get_memory.restype = wintypes.BOOL
    counters = MemoryCounters(size=ctypes.sizeof(MemoryCounters))
    if get_memory(kernel.GetCurrentProcess(), ctypes.byref(counters), counters.size):
        return int(counters.peak_working_set)
    return None


def run_experiment(training, directory):
    if directory.exists():
        raise FileExistsError("Choose a fresh local output directory for a new reproduction")
    wall_start, cpu_start = perf_counter(), process_time()
    data, raw_groups = load_pinned_training(training)
    partitions = development_partitions(data.labels, data.groups)
    audit = audit_partitions(data.labels, raw_groups, data.groups, partitions)
    directory.mkdir(parents=True, exist_ok=False)
    split_path = directory / "partitions.npz"
    np.savez_compressed(split_path, **partitions)
    audit["training_sha256"] = TRAINING_SHA256
    audit["row_index_archive_sha256"] = sha256_file(split_path)
    write_report(directory / "split-audit.json", audit)
    if not audit["training_allowed"]:
        raise ValueError(f"Split gates failed. See {directory / 'split-audit.json'}")
    print("Four split gates passed. Keeping all original rows.", file=sys.stderr, flush=True)

    def samples(role):
        indices = partitions[role]
        return data.predictors[indices], data.labels[indices]

    with threadpool_limits(limits=THREADS):
        pipeline, selection = train_candidates(data.columns, samples("fit"), samples("calibration"), samples("comparison"))
        frozen = pickle.dumps(pipeline, protocol=pickle.HIGHEST_PROTOCOL)
        with (directory / "selected-pipeline.pkl").open("xb") as stream:
            stream.write(frozen)
        threshold = selection["candidates"][selection["selected"]]["threshold"]
        selection.update({
            "threshold": threshold, "decision_rule": "attack score >= threshold", "recall_floor": RECALL_FLOOR,
            "pipeline_sha256": sha256(frozen).hexdigest(), "feature_columns": data.columns,
            "categorical_columns": list(CATEGORICAL_COLUMNS), "training_sha256": TRAINING_SHA256,
            "split_audit_sha256": sha256_file(directory / "split-audit.json"),
            "model_seed": RANDOM_SEED, "importance_seed": IMPORTANCE_SEED,
            "importance_repeats": IMPORTANCE_REPEATS, "native_thread_limit": THREADS,
            "versions": {"python": platform.python_version(), **{name: version(name) for name in DEPENDENCIES}},
        })
        write_report(directory / "selection.json", selection)
        print(f"Frozen {selection['selected']} at {threshold:.10g}. Scoring final development validation once.",
              file=sys.stderr, flush=True)
        final = evaluate_frozen(directory, pipeline, threshold, samples("final_validation"))
    final.update({"selected": selection["selected"], "threshold": threshold,
                  "selection_sha256": sha256_file(directory / "selection.json"),
                  "total_wall_seconds": perf_counter() - wall_start, "total_process_cpu_seconds": process_time() - cpu_start,
                  "peak_process_rss_bytes": peak_rss_bytes()})
    write_report(directory / "final-validation.json", final)
    return final


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--training", type=Path, default=TRAINING_CSV)
    parser.add_argument("--output", type=Path, default=Path("data/g32-ml-baselines"))
    args = parser.parse_args(argv)
    data_root, directory = Path("data").resolve(), args.output.resolve()
    if directory == data_root or not directory.is_relative_to(data_root):
        parser.error("choose a new output directory under the local ignored data/ directory")
    try:
        result = run_experiment(args.training, directory)
    except (OSError, ValueError) as error:
        parser.exit(1, f"G32 stopped: {error}\n")
    print(json.dumps(result, indent=2, allow_nan=False))


if __name__ == "__main__":
    main()
