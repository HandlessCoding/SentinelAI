"""Prespecified candidates and fold-level evaluation for G32.1."""

from statistics import mean, stdev
from time import perf_counter, process_time
import warnings

import numpy as np
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.inspection import permutation_importance
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import balanced_accuracy_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OrdinalEncoder

from ml.run_baseline import CATEGORICAL_COLUMNS, RANDOM_SEED, binary_metrics, build_pipeline, class_distribution
from ml.run_model_comparison import FOREST_PARAMS
from ml.run_unsw_development import RECALL_FLOOR, peak_rss_bytes, select_recall_threshold
from ml.unsw_overnight_data import FEATURE_SETS


NATIVE_THREADS = 2
FOREST_WORKERS = 3
IMPORTANCE_SEED = 32144
IMPORTANCE_ROWS = 384
MONITORED_FIELDS = ("sttl", "dttl", "ct_state_ttl", "ct_srv_dst", "ct_dst_src_ltm", "is_sm_ips_ports")
HISTOGRAM = {"max_iter": 100, "learning_rate": 0.1, "max_leaf_nodes": 31, "min_samples_leaf": 20,
             "l2_regularization": 1.0, "early_stopping": False, "random_state": RANDOM_SEED}
FOREST = {**FOREST_PARAMS, "n_jobs": FOREST_WORKERS}
LOGISTIC = {"solver": "liblinear", "max_iter": 1000, "random_state": RANDOM_SEED}
RECIPES = (
    ("hgb-reference", "hgb", HISTOGRAM),
    ("hgb-regularized", "hgb", {**HISTOGRAM, "max_iter": 140, "learning_rate": 0.065,
                                 "min_samples_leaf": 45, "l2_regularization": 5.0}),
    ("hgb-compact", "hgb", {**HISTOGRAM, "max_leaf_nodes": 15, "min_samples_leaf": 35, "l2_regularization": 2.0}),
    ("hgb-balanced", "hgb", {**HISTOGRAM, "max_iter": 110, "class_weight": "balanced"}),
    ("rf-reference", "rf", FOREST),
    ("rf-wider", "rf", {**FOREST, "n_estimators": 64, "max_depth": 18, "max_leaf_nodes": 1_024,
                        "min_samples_leaf": 4}),
    ("rf-balanced", "rf", {**FOREST, "n_estimators": 56, "class_weight": "balanced_subsample"}),
    ("lr-reference", "lr", LOGISTIC),
    ("lr-balanced-regularized", "lr", {**LOGISTIC, "C": 0.25, "class_weight": "balanced"}),
)
METRICS = ("accuracy", "balanced_accuracy", "precision", "recall", "false_positive_rate")


def configurations(*, smoke=False):
    result = [
        {"id": f"{name}-{feature_set}", "recipe": name, "family": family,
         "parameters": parameters, "feature_set": feature_set}
        for name, family, parameters in RECIPES for feature_set in FEATURE_SETS
    ]
    if smoke:
        return [item for item in result if item["id"] in {"hgb-reference-full", "rf-reference-no_ttl"}]
    return result


def make_pipeline(config, columns):
    parameters = config["parameters"]
    if config["family"] == "rf":
        return build_pipeline(columns, RandomForestClassifier(**parameters))
    if config["family"] == "lr":
        return build_pipeline(columns, LogisticRegression(**parameters))
    categorical = [columns.index(name) for name in CATEGORICAL_COLUMNS]
    numeric = [i for i in range(len(columns)) if i not in categorical]
    preprocess = ColumnTransformer([
        ("categorical", OrdinalEncoder(handle_unknown="use_encoded_value", unknown_value=np.nan), categorical),
        ("numeric", "passthrough", numeric),
    ])
    classifier = HistGradientBoostingClassifier(**parameters, categorical_features=list(range(len(categorical))))
    return Pipeline([("preprocessor", preprocess), ("classifier", classifier)])


def diagnostic_importance(model, features, labels, threshold, columns, fold):
    seed = IMPORTANCE_SEED + fold
    indices = np.random.default_rng(seed).choice(len(labels), min(IMPORTANCE_ROWS, len(labels)), replace=False)

    def score(estimator, predictors, expected):
        return balanced_accuracy_score(expected, estimator.predict_proba(predictors)[:, 1] >= threshold)

    effect = permutation_importance(model, features[indices], labels[indices], scoring=score, n_repeats=1,
                                    random_state=seed, n_jobs=1).importances_mean
    return {"rows": len(indices), "class_counts": class_distribution(labels[indices]),
            "balanced_accuracy_drop": {name: float(value) for name, value in zip(columns, effect, strict=True)}}


def fit_fold(config, columns, features, labels, roles, fold, guard):
    wall, cpu = perf_counter(), process_time()
    pipeline = make_pipeline(config, columns)
    fitting, calibration, evaluation = (roles[role] for role in ("fit", "calibration", "evaluation"))
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        pipeline.fit(features[fitting], labels[fitting])
        fit_seconds = perf_counter() - wall
        guard()
        calibration_scores = pipeline.predict_proba(features[calibration])[:, 1]
        threshold = select_recall_threshold(labels[calibration], calibration_scores)
        evaluation_features, evaluation_labels = features[evaluation], labels[evaluation]
        scores = pipeline.predict_proba(evaluation_features)[:, 1]
        if not np.isfinite(scores).all():
            raise ValueError("Nonfinite evaluation scores")
        guard()
        importance = (diagnostic_importance(pipeline, evaluation_features, evaluation_labels, threshold, columns, fold)
                      if config["feature_set"] == "full" else None)
    return {
        "fold": fold, "threshold": threshold,
        "class_counts": {role: class_distribution(labels[indices]) for role, indices in roles.items()},
        "calibration": binary_metrics(labels[calibration], calibration_scores >= threshold),
        "calibrated": binary_metrics(evaluation_labels, scores >= threshold),
        "default": binary_metrics(evaluation_labels, scores > 0.5),
        "importance": importance, "fit_seconds": fit_seconds, "wall_seconds": perf_counter() - wall,
        "cpu_seconds": process_time() - cpu, "peak_process_rss_bytes_so_far": peak_rss_bytes(),
        "warnings": sorted({f"{item.category.__name__}: {item.message}" for item in caught}),
    }


def aggregate_folds(folds):
    return {policy: {metric: spread([row[policy][metric] for row in folds]) for metric in METRICS}
            for policy in ("default", "calibrated")}


def spread(values):
    return {"mean": mean(values), "stdev": stdev(values) if len(values) > 1 else None,
            "min": min(values), "max": max(values)}


def rank_candidates(completed):
    """Prioritize passing the recall floor on every evaluation fold."""
    def rank(item):
        metrics = item["aggregate"]["calibrated"]
        recall = metrics["recall"]["min"]
        fpr = metrics["false_positive_rate"]
        if recall >= RECALL_FLOOR:
            return 0, fpr["mean"], fpr["max"], -recall, item["config"]["id"]
        return 1, -recall, fpr["mean"], fpr["max"], item["config"]["id"]

    return sorted(completed, key=rank)
