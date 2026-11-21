"""Compare a bounded Random Forest to G2 on the same training-data folds."""

import argparse
import csv
from hashlib import file_digest
from importlib.metadata import version
import json
import logging
import pickle
import platform
import sys
from time import perf_counter
import warnings

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, roc_auc_score
from threadpoolctl import threadpool_limits

from ml.run_baseline import (
    DEPENDENCIES,
    FOLD_COUNT,
    RANDOM_SEED,
    SMOKE_ROWS,
    TRAINING_CSV,
    TrainingData,
    binary_metrics,
    build_pipeline,
    class_distribution,
    load_training,
)
from ml.run_threshold_analysis import BUDGETS, INNER_FOLDS, INNER_SEED, checked_splits, select_threshold


FOREST_PARAMS = {
    "n_estimators": 48,
    "max_depth": 14,
    "max_leaf_nodes": 512,
    "min_samples_leaf": 5,
    "max_samples": 0.75,
    "max_features": "sqrt",
    "n_jobs": 1,
    "random_state": RANDOM_SEED,
}
LOGISTIC = "logistic_regression"
FOREST = "random_forest"
LOGGER = logging.getLogger(__name__)


def comparison_pipelines(columns):
    """Build fresh pipelines with the G2 preprocessing for both estimators."""
    return {
        LOGISTIC: build_pipeline(
            columns, LogisticRegression(solver="liblinear", max_iter=1000, random_state=RANDOM_SEED)
        ),
        FOREST: forest_pipeline(columns),
    }


def forest_pipeline(columns):
    return build_pipeline(columns, RandomForestClassifier(**FOREST_PARAMS))


def fit_and_score(pipeline, data, train, validation, *, measure_size=False):
    """Measure pipeline fit and batch probability inference on preloaded rows."""
    x_train, y_train = data.predictors[train], data.labels[train]
    x_validation = data.predictors[validation]
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        start = perf_counter()
        pipeline.fit(x_train, y_train)
        train_seconds = perf_counter() - start
        start = perf_counter()
        scores = pipeline.predict_proba(x_validation)[:, 1]
        prediction_seconds = perf_counter() - start
    if not np.isfinite(scores).all():
        raise RuntimeError("Model produced non-finite attack scores")

    cost = {"train_seconds": train_seconds, "prediction_seconds": prediction_seconds}
    if measure_size:
        cost["pipeline_bytes"] = len(pickle.dumps(pipeline, protocol=pickle.HIGHEST_PROTOCOL))
    return scores, cost, [f"{item.category.__name__}: {item.message}" for item in caught]


def default_metrics(labels, scores):
    """Evaluate the default rule with score ties at 0.5 assigned to normal."""
    return {
        **binary_metrics(labels, scores > 0.5),
        "roc_auc": float(roc_auc_score(labels, scores)),
        "average_precision": float(average_precision_score(labels, scores)),
    }


def inner_forest_predictions(data):
    """Collect inner out-of-fold scores using only the current outer training subset."""
    scores = np.full(len(data.labels), np.nan)
    audit = []
    for number, (train, validation, split) in enumerate(
        checked_splits(data.labels, data.groups, INNER_FOLDS, INNER_SEED), start=1
    ):
        if not np.isnan(scores[validation]).all():
            raise RuntimeError("Inner validation rows were scored more than once")
        LOGGER.info("  Forest inner fit %d/%d", number, INNER_FOLDS)
        scores[validation], _, fit_warnings = fit_and_score(
            forest_pipeline(data.columns), data, train, validation
        )
        audit.append({"fold": number, **split, "warnings": fit_warnings})
    if not np.isfinite(scores).all():
        raise RuntimeError("Inner folds must score every outer training row")
    return scores, audit


def evaluate_forest_thresholds(data, splits, outer_scores):
    """Choose thresholds from inner predictions and evaluate saved outer scores."""
    decisions = {name: np.full(len(data.labels), -1, dtype=np.int8) for name in BUDGETS}
    folds = []
    for number, (train, validation, _) in enumerate(splits, start=1):
        LOGGER.info("Threshold analysis, outer fold %d/%d", number, FOLD_COUNT)
        inner_data = TrainingData(
            data.columns, data.predictors[train], data.labels[train], data.groups[train]
        )
        inner_scores, audit = inner_forest_predictions(inner_data)
        selections = {
            name: select_threshold(inner_data.labels, inner_scores, budget)
            for name, budget in BUDGETS.items()
        }
        points = {}
        for name, choice in selections.items():
            if choice is None:
                points[name] = {
                    "threshold": None,
                    "status": "No finite threshold predicting any attack met the inner budget",
                    "outer_budget_met": None,
                    "metrics": None,
                }
                continue
            decisions[name][validation] = outer_scores[validation] >= choice["threshold"]
            metrics = binary_metrics(data.labels[validation], decisions[name][validation])
            points[name] = {
                **choice,
                "metrics": metrics,
                "outer_budget_met": metrics["false_positive_rate"] <= BUDGETS[name],
            }
        folds.append({"fold": number, "inner_folds": audit, "operating_points": points})

    pooled = {}
    for name, predicted in decisions.items():
        complete = (predicted >= 0).all()
        metrics = binary_metrics(data.labels, predicted) if complete else None
        verdicts = [fold["operating_points"][name]["outer_budget_met"] for fold in folds]
        pooled[name] = {
            "metrics": metrics,
            "folds_with_threshold": sum(value is not None for value in verdicts),
            "folds_within_budget": sum(value is True for value in verdicts),
            "pooled_budget_met": metrics["false_positive_rate"] <= BUDGETS[name] if complete else None,
        }
    return {"inner_seed": INNER_SEED, "budgets": BUDGETS, "folds": folds, "pooled": pooled}


def compare_models(data, *, allow_thresholds=True):
    """Compare both models on identical outer folds with bounded native threads."""
    splits = list(checked_splits(data.labels, data.groups, FOLD_COUNT, RANDOM_SEED))
    models = (LOGISTIC, FOREST)
    outer_scores = {name: np.full(len(data.labels), np.nan) for name in models}
    folds = []
    with threadpool_limits(limits=1):
        for number, (train, validation, split) in enumerate(splits, start=1):
            results = {}
            for name, pipeline in comparison_pipelines(data.columns).items():
                if not np.isnan(outer_scores[name][validation]).all():
                    raise RuntimeError("Outer validation rows were scored more than once")
                LOGGER.info("Outer fold %d/%d, fitting %s", number, FOLD_COUNT, name)
                scores, cost, fit_warnings = fit_and_score(
                    pipeline, data, train, validation, measure_size=True
                )
                outer_scores[name][validation] = scores
                results[name] = {
                    "metrics": default_metrics(data.labels[validation], scores),
                    "cost": cost,
                    "warnings": fit_warnings,
                }
            folds.append({"fold": number, **split, "models": results})

        pooled = {}
        for name, scores in outer_scores.items():
            if not np.isfinite(scores).all():
                raise RuntimeError("Outer folds must score every row")
            costs = [fold["models"][name]["cost"] for fold in folds]
            pooled[name] = {
                "metrics": default_metrics(data.labels, scores),
                "total_train_seconds": sum(cost["train_seconds"] for cost in costs),
                "total_prediction_seconds": sum(cost["prediction_seconds"] for cost in costs),
                "mean_pipeline_bytes": float(np.mean([cost["pipeline_bytes"] for cost in costs])),
            }

        # The prespecified screen governs whether to run the exploratory stage.
        # Threshold candidates and their scores come only from inner folds.
        promising = all(
            pooled[FOREST]["metrics"][metric] > pooled[LOGISTIC]["metrics"][metric]
            for metric in ("balanced_accuracy", "roc_auc")
        )
        thresholds = None
        if allow_thresholds and promising:
            LOGGER.info("Forest improved pooled balanced accuracy and ROC AUC. Starting inner fits.")
            thresholds = evaluate_forest_thresholds(data, splits, outer_scores[FOREST])
    return {
        "outer_seed": RANDOM_SEED,
        "forest_parameters": FOREST_PARAMS,
        "classes": class_distribution(data.labels),
        "raw_predictor_groups": int(np.unique(data.groups).size),
        "folds": folds,
        "pooled": pooled,
        "promising": promising,
        "forest_thresholds": thresholds,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--smoke", action="store_true", help="use up to 600 evenly spaced training rows")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    try:
        data = load_training(TRAINING_CSV)
        if args.smoke:
            sample_size = min(SMOKE_ROWS, len(data.labels))
            sample = np.linspace(0, len(data.labels) - 1, sample_size, dtype=int)
            data = TrainingData(
                data.columns, data.predictors[sample], data.labels[sample], data.groups[sample]
            )
        report = compare_models(data, allow_thresholds=not args.smoke)
        with TRAINING_CSV.open("rb") as file:
            digest = file_digest(file, "sha256").hexdigest()
    except (OSError, ValueError, csv.Error, RuntimeError) as error:
        print(f"Model comparison failed: {error}", file=sys.stderr)
        return 1

    versions = {"python": platform.python_version()}
    versions.update({name: version(name) for name in DEPENDENCIES})
    print(json.dumps({
        "mode": "smoke" if args.smoke else "full",
        "versions": versions,
        "training_csv_sha256": digest,
        **report,
    }, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
