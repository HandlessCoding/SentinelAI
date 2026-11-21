"""Evaluate logistic-regression thresholds with nested group cross-validation."""

import argparse
import csv
from hashlib import file_digest
from importlib.metadata import version
import json
import logging
from pathlib import Path
import platform
import sys
import warnings

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    average_precision_score,
    precision_recall_curve,
    roc_auc_score,
    roc_curve,
)
from sklearn.model_selection import StratifiedGroupKFold

from ml.run_baseline import (
    DEPENDENCIES,
    FOLD_COUNT,
    RANDOM_SEED,
    TRAINING_CSV,
    binary_metrics,
    build_pipeline,
    class_distribution,
    load_training,
)


INNER_SEED = 43
INNER_FOLDS = 3
BUDGETS = {"5_percent": 0.05, "10_percent": 0.10}
LOGGER = logging.getLogger(__name__)


def select_threshold(labels, scores, budget):
    """Return the best finite ROC operating point within the FPR budget."""
    if not 0 <= budget <= 1 or set(np.unique(labels)) != {0, 1}:
        raise ValueError("Threshold selection needs a budget in [0, 1] and both classes")
    false_positive_rates, recalls, thresholds = roc_curve(
        labels, scores, drop_intermediate=False
    )
    # The initial infinity threshold predicts every record as normal.
    eligible = np.flatnonzero(np.isfinite(thresholds) & (false_positive_rates <= budget))
    if not eligible.size:
        return None

    # ROC orders candidates from highest threshold to lowest. On equal recall,
    # the first candidate has the lowest FPR, then the highest threshold.
    best = eligible[np.argmax(recalls[eligible])]
    return {
        "threshold": float(thresholds[best]),
        "inner_recall": float(recalls[best]),
        "inner_false_positive_rate": float(false_positive_rates[best]),
    }


def checked_splits(labels, groups, n_splits, seed):
    """Yield indices relative to these labels and verify separation by group."""
    splitter = StratifiedGroupKFold(n_splits=n_splits, shuffle=True, random_state=seed)
    for train, validation in splitter.split(np.arange(len(labels)), labels, groups):
        train_groups = np.unique(groups[train])
        validation_groups = np.unique(groups[validation])
        overlap = np.intersect1d(train_groups, validation_groups, assume_unique=True).size
        if overlap:
            raise RuntimeError(f"Split shares {overlap} raw predictor groups")
        train_classes = class_distribution(labels[train])
        validation_classes = class_distribution(labels[validation])
        if 0 in train_classes.values() or 0 in validation_classes.values():
            raise ValueError("Each training and validation subset needs both classes")
        yield train, validation, {
            "train_groups": int(train_groups.size),
            "validation_groups": int(validation_groups.size),
            "overlapping_groups": int(overlap),
            "train_classes": train_classes,
            "validation_classes": validation_classes,
        }


def fit_attack_scores(data, train, validation):
    """Fit a fresh G2 pipeline on train and return attack scores for validation."""
    pipeline = build_pipeline(
        data.columns,
        LogisticRegression(solver="liblinear", max_iter=1000, random_state=RANDOM_SEED),
    )
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        pipeline.fit(data.predictors[train], data.labels[train])
        scores = pipeline.predict_proba(data.predictors[validation])[:, 1]
    return scores, [f"{item.category.__name__}: {item.message}" for item in caught]


def inner_predictions(data, outer_train, outer_fold):
    """Score each outer-training row once using an inner fit that excluded it."""
    labels = data.labels[outer_train]
    groups = data.groups[outer_train]
    scores = np.full(len(outer_train), np.nan)
    audit = []
    for number, (train, validation, split) in enumerate(
        checked_splits(labels, groups, INNER_FOLDS, INNER_SEED), start=1
    ):
        if not np.isnan(scores[validation]).all():
            raise RuntimeError("Inner validation rows were scored more than once")
        LOGGER.info("Outer fold %d, inner fit %d/%d", outer_fold, number, INNER_FOLDS)
        scores[validation], fit_warnings = fit_attack_scores(
            data, outer_train[train], outer_train[validation]
        )
        audit.append({"fold": number, **split, "warnings": fit_warnings})
    if not np.isfinite(scores).all():
        raise RuntimeError("Inner predictions must cover all outer-training rows")
    return labels, scores, audit


def nested_evaluation(data):
    """Commit thresholds before fitting and scoring each outer evaluation split."""
    labels = data.labels
    outer_scores = np.full(len(labels), np.nan)
    predictions = {
        name: np.full(len(labels), -1, dtype=np.int8) for name in ("default", *BUDGETS)
    }
    folds = []
    for number, (train, validation, split) in enumerate(
        checked_splits(labels, data.groups, FOLD_COUNT, RANDOM_SEED), start=1
    ):
        if not np.isnan(outer_scores[validation]).all():
            raise RuntimeError("Outer validation rows were scored more than once")
        inner_labels, inner_scores, inner_audit = inner_predictions(data, train, number)
        selections = {
            name: select_threshold(inner_labels, inner_scores, budget)
            for name, budget in BUDGETS.items()
        }
        LOGGER.info("Outer fold %d, final fit with thresholds fixed", number)
        scores, fit_warnings = fit_attack_scores(data, train, validation)
        outer_scores[validation] = scores

        # Match G2's prediction rule, including assigning a score of 0.5 to normal.
        predictions["default"][validation] = scores > 0.5
        operating_points = {
            "default": {
                "threshold": 0.5,
                "metrics": binary_metrics(labels[validation], predictions["default"][validation]),
            }
        }
        for name, choice in selections.items():
            if choice is None:
                operating_points[name] = {
                    "threshold": None,
                    "status": "No finite threshold predicting any attack met the inner budget",
                    "outer_budget_met": None,
                    "metrics": None,
                }
                continue
            predictions[name][validation] = scores >= choice["threshold"]
            metrics = binary_metrics(labels[validation], predictions[name][validation])
            operating_points[name] = {
                **choice,
                "outer_budget_met": metrics["false_positive_rate"] <= BUDGETS[name],
                "metrics": metrics,
            }
        folds.append({
            "fold": number,
            **split,
            "inner_folds": inner_audit,
            "warnings": fit_warnings,
            "operating_points": operating_points,
        })

    if not np.isfinite(outer_scores).all():
        raise RuntimeError("Outer predictions must cover all training CSV rows")
    aggregate = {}
    for name, values in predictions.items():
        complete = (values >= 0).all()
        metrics = binary_metrics(labels, values) if complete else None
        aggregate[name] = {"metrics": metrics}
        if name in BUDGETS:
            fold_verdicts = [fold["operating_points"][name]["outer_budget_met"] for fold in folds]
            aggregate[name].update({
                "folds_with_threshold": sum(verdict is not None for verdict in fold_verdicts),
                "folds_within_budget": sum(verdict is True for verdict in fold_verdicts),
                "pooled_budget_met": metrics["false_positive_rate"] <= BUDGETS[name]
                if complete else None,
            })
    return {
        "outer_seed": RANDOM_SEED,
        "inner_seed": INNER_SEED,
        "budgets": BUDGETS,
        "classes": class_distribution(labels),
        "raw_predictor_groups": int(np.unique(data.groups).size),
        "folds": folds,
        "pooled": aggregate,
        "curves": {
            "roc_auc": float(roc_auc_score(labels, outer_scores)),
            "average_precision": float(average_precision_score(labels, outer_scores)),
        },
    }, outer_scores


def save_curves(path, labels, scores, report, figure_class):
    """Plot score curves and the pooled outcomes of the three decision policies."""
    figure = figure_class(figsize=(10, 4.6), layout="constrained")
    roc_axis, pr_axis = figure.subplots(1, 2)
    fpr, recall_roc, _ = roc_curve(labels, scores)
    precision, recall_pr, _ = precision_recall_curve(labels, scores, drop_intermediate=True)
    roc_axis.plot(fpr, recall_roc, color="#183b60", label=f"AUC {report['curves']['roc_auc']:.4f}")
    roc_axis.plot([0, 1], [0, 1], "--", color="#687583", linewidth=1, label="Chance")
    pr_axis.step(
        recall_pr, precision, where="post", color="#183b60",
        label=f"Average precision {report['curves']['average_precision']:.4f}",
    )
    pr_axis.axhline(labels.mean(), color="#687583", linestyle="--", linewidth=1, label="Prevalence")
    for name, label, color, marker in (
        ("default", "Default 0.5", "#6530a5", "o"),
        ("5_percent", "5% policy", "#b9460f", "^"),
        ("10_percent", "10% policy", "#057666", "s"),
    ):
        metrics = report["pooled"][name]["metrics"]
        if metrics is not None:
            roc_axis.scatter(
                metrics["false_positive_rate"], metrics["recall"],
                label=label, color=color, marker=marker, zorder=4,
            )
            pr_axis.scatter(
                metrics["recall"], metrics["precision"],
                label=label, color=color, marker=marker, zorder=4,
            )
    for budget in BUDGETS.values():
        roc_axis.axvline(budget, color="#b9bfc7", linestyle=":", linewidth=1)

    roc_axis.set(title="Receiver operating characteristic", xlabel="False-positive rate", ylabel="Attack recall")
    pr_axis.set(title="Precision–recall", xlabel="Attack recall", ylabel="Attack precision")
    for axis in (roc_axis, pr_axis):
        axis.set_xlim(-0.01, 1.01)
        axis.set_ylim(-0.01, 1.02)
        axis.grid(alpha=0.2)
        axis.legend(loc="lower right", fontsize=8)
    figure.suptitle("Logistic regression | Pooled outer-fold predictions")
    figure.savefig(path, dpi=180)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plot", type=Path, help="save ROC and precision–recall curves to this PNG path")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    versions = {"python": platform.python_version()}
    versions.update({name: version(name) for name in DEPENDENCIES})
    try:
        if args.plot:
            from matplotlib.figure import Figure

            versions["matplotlib"] = version("matplotlib")
        data = load_training(TRAINING_CSV)
        with TRAINING_CSV.open("rb") as file:
            digest = file_digest(file, "sha256").hexdigest()
        report, scores = nested_evaluation(data)
        report.update({"versions": versions, "training_csv_sha256": digest})
        print(json.dumps(report, indent=2), flush=True)
        if args.plot:
            save_curves(args.plot, data.labels, scores, report, Figure)
    except (ImportError, OSError, ValueError, csv.Error, RuntimeError) as error:
        print(f"Threshold analysis failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
