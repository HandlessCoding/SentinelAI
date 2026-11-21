"""Compare two binary classifiers using only the UNSW-NB15 training partition."""

import argparse
import csv
from dataclasses import dataclass
from hashlib import file_digest
from importlib.metadata import version
import json
from pathlib import Path
import platform
import sys
import warnings

import numpy as np
from sklearn.compose import ColumnTransformer
from sklearn.dummy import DummyClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

from ml.inspect_dataset import read_header, read_rows


TRAINING_CSV = Path("data/UNSW_NB15_training-set.csv")
EXCLUDED_COLUMNS = {"id", "label", "attack_cat"}
CATEGORICAL_COLUMNS = ("proto", "service", "state", "is_ftp_login")
RANDOM_SEED = 42
FOLD_COUNT = 3
SMOKE_ROWS = 600
DEPENDENCIES = ("scikit-learn", "numpy", "scipy", "joblib", "threadpoolctl")


@dataclass
class TrainingData:
    columns: list[str]
    predictors: np.ndarray
    labels: np.ndarray
    groups: np.ndarray


def load_training(path: Path) -> TrainingData:
    """Assign the same group ID to identical raw predictor tuples."""
    group_ids = {}
    predictors = []
    labels = []
    groups = []

    with path.open(encoding="utf-8-sig", newline="") as file:
        reader = csv.reader(file, strict=True)
        header = read_header(reader)
        columns = [name for name in header if name not in EXCLUDED_COLUMNS]
        if missing := set(CATEGORICAL_COLUMNS).difference(columns):
            raise ValueError(f"Missing categorical columns: {', '.join(sorted(missing))}")
        predictor_indices = [
            index for index, name in enumerate(header) if name not in EXCLUDED_COLUMNS
        ]
        label_index = header.index("label")

        for row in read_rows(reader, header):
            label = row[label_index]
            if label not in {"0", "1"}:
                raise ValueError(f"CSV line {reader.line_num} has an invalid binary label")
            # Keep the original strings until grouping is complete.
            vector = tuple(row[index] for index in predictor_indices)
            predictors.append(vector)
            groups.append(group_ids.setdefault(vector, len(group_ids)))
            labels.append(int(label))

    if not predictors:
        raise ValueError("Training CSV contains no data rows")

    return TrainingData(
        columns, np.array(predictors, dtype=object), np.array(labels), np.array(groups)
    )


def build_pipeline(columns, classifier):
    """Create an unfitted preprocessor and classifier for a single fold."""
    categorical = [columns.index(name) for name in CATEGORICAL_COLUMNS]
    numeric = [index for index, name in enumerate(columns) if name not in CATEGORICAL_COLUMNS]
    preprocessor = ColumnTransformer(
        [
            ("categorical", OneHotEncoder(handle_unknown="ignore"), categorical),
            ("numeric", StandardScaler(), numeric),
        ]
    )
    return Pipeline([("preprocessor", preprocessor), ("classifier", classifier)])


def class_distribution(labels):
    normal, attack = np.bincount(labels, minlength=2)
    return {"normal": int(normal), "attack": int(attack)}


def binary_metrics(actual, predicted):
    """Use attack (1) as positive and order the confusion matrix as [0, 1]."""
    matrix = confusion_matrix(actual, predicted, labels=[0, 1])
    true_negative, false_positive = matrix[0]
    normal_count = true_negative + false_positive
    return {
        "accuracy": float(accuracy_score(actual, predicted)),
        "balanced_accuracy": float(balanced_accuracy_score(actual, predicted)),
        "precision": float(precision_score(actual, predicted, zero_division=0)),
        "recall": float(recall_score(actual, predicted, zero_division=0)),
        "f1": float(f1_score(actual, predicted, zero_division=0)),
        "false_positive_rate": float(false_positive / normal_count) if normal_count else None,
        "confusion_matrix": matrix.tolist(),
    }


def run_baseline(data: TrainingData):
    """Fit fresh pipelines and evaluate both models on the same three folds."""
    splitter = StratifiedGroupKFold(
        n_splits=FOLD_COUNT, shuffle=True, random_state=RANDOM_SEED
    )
    folds = []
    for fold_number, (train, validation) in enumerate(
        splitter.split(data.predictors, data.labels, data.groups), start=1
    ):
        train_groups = np.unique(data.groups[train])
        validation_groups = np.unique(data.groups[validation])
        overlap = np.intersect1d(train_groups, validation_groups, assume_unique=True).size
        if overlap:
            raise RuntimeError(f"Fold {fold_number} shares {overlap} predictor groups")

        y_train, y_validation = data.labels[train], data.labels[validation]
        train_distribution = class_distribution(y_train)
        validation_distribution = class_distribution(y_validation)
        if 0 in train_distribution.values() or 0 in validation_distribution.values():
            raise ValueError(f"Fold {fold_number} requires both classes in each partition")

        fold = {
            "fold": fold_number,
            "train_classes": train_distribution,
            "validation_classes": validation_distribution,
            "train_groups": int(train_groups.size),
            "validation_groups": int(validation_groups.size),
            "overlapping_groups": int(overlap),
            "models": {},
        }
        x_train, x_validation = data.predictors[train], data.predictors[validation]
        classifiers = {
            "dummy": DummyClassifier(strategy="most_frequent"),
            "logistic_regression": LogisticRegression(
                solver="liblinear", max_iter=1000, random_state=RANDOM_SEED
            ),
        }
        for name, classifier in classifiers.items():
            pipeline = build_pipeline(data.columns, classifier)
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                pipeline.fit(x_train, y_train)
                predicted = pipeline.predict(x_validation)
                metrics = binary_metrics(y_validation, predicted)
            fold["models"][name] = {
                "metrics": metrics,
                "warnings": [f"{item.category.__name__}: {item.message}" for item in caught],
            }
        folds.append(fold)

    summary = {}
    for name, model in folds[0]["models"].items():
        summary[name] = {}
        for metric in model["metrics"]:
            values = np.asarray([fold["models"][name]["metrics"][metric] for fold in folds])
            summary[name][metric] = {
                "mean": values.mean(axis=0).tolist(),
                "std": values.std(axis=0, ddof=0).tolist(),
            }

    return {
        "seed": RANDOM_SEED,
        "predictor_count": len(data.columns),
        "classes": class_distribution(data.labels),
        "distinct_groups": int(np.unique(data.groups).size),
        "folds": folds,
        "summary": summary,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--smoke", action="store_true", help="fit on up to 600 evenly spaced training rows"
    )
    args = parser.parse_args(argv)
    try:
        data = load_training(TRAINING_CSV)
        if args.smoke:
            sample_size = min(SMOKE_ROWS, len(data.labels))
            sample = np.linspace(0, len(data.labels) - 1, sample_size, dtype=int)
            data = TrainingData(
                data.columns, data.predictors[sample], data.labels[sample], data.groups[sample]
            )

        report = run_baseline(data)
        with TRAINING_CSV.open("rb") as file:
            training_digest = file_digest(file, "sha256").hexdigest()
    except (OSError, ValueError, csv.Error, RuntimeError) as error:
        print(f"Baseline failed: {error}", file=sys.stderr)
        return 1

    versions = {"python": platform.python_version()}
    versions.update({name: version(name) for name in DEPENDENCIES})
    output = {
        "mode": "smoke" if args.smoke else "full",
        "training_csv_sha256": training_digest,
        "versions": versions,
        **report,
    }
    print(json.dumps(output, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
