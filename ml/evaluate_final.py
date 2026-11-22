"""Evaluate the frozen SentinelAI Random Forest on the official test partition."""

import argparse
from collections import Counter
import csv
from hashlib import file_digest, sha256
from io import TextIOWrapper
from itertools import batched
import json
import math
from pathlib import Path
from shutil import copyfileobj
import sys
from tempfile import TemporaryFile

import numpy as np
from sklearn.metrics import average_precision_score, roc_auc_score

from ml.inference import (
    DEFAULT_ARTIFACT_DIR,
    FEATURE_TYPES,
    FROZEN_PIPELINE_SHA256,
    InferenceModel,
    feature_schema,
    load_model,
    read_prediction_csv,
    read_prediction_rows,
)
from ml.run_baseline import TRAINING_CSV, binary_metrics, class_distribution


TEST_CSV = Path("data/UNSW_NB15_testing-set.csv")
FROZEN_VERSION = "unsw-nb15-rf-v1"
FROZEN_THRESHOLD = 0.5
FROZEN_TRAINING_SHA256 = "bec7dd5ec88dc2a0ccc7a07879d338395ed7421750f675fd0339e07dfe0648fa"
FROZEN_TEST_SHA256 = "734fe6642edf758f7c94d7d9149426b49d202fe8e7bf0bef47392489c3c0a559"
FROZEN_SCHEMA_SHA256 = "474c13dcaf34dff990839d6ccd7e5bc88702d88df551cdc5d2c3005c2f30417d"
EXPECTED_TRAINING_ROWS = 175_341
EXPECTED_TEST_ROWS = 82_332
BATCH_SIZE = 1_000


def sha256_file(path: Path) -> str:
    with path.open("rb") as stream:
        return file_digest(stream, "sha256").hexdigest()


def load_frozen_model(artifact_dir: Path, training_path: Path) -> tuple[InferenceModel, dict]:
    """Verify the locked model, ordered schema, threshold and training provenance."""
    metadata = json.loads((artifact_dir / "metadata.json").read_text(encoding="utf-8"))
    if not isinstance(metadata, dict):
        raise ValueError("Invalid model metadata")
    schema = feature_schema()
    schema_bytes = json.dumps(schema, sort_keys=True, separators=(",", ":")).encode()
    if (
        metadata.get("model_version") != FROZEN_VERSION
        or metadata.get("decision_threshold") != FROZEN_THRESHOLD
        or metadata.get("feature_schema") != schema
        or sha256(schema_bytes).hexdigest() != FROZEN_SCHEMA_SHA256
    ):
        raise ValueError("Manifest does not match the frozen model version, schema or threshold")
    if metadata.get("pipeline_sha256") != FROZEN_PIPELINE_SHA256:
        raise ValueError("Pipeline SHA-256 does not match the frozen G5 artifact")
    training = metadata.get("training")
    if (
        not isinstance(training, dict)
        or training.get("sha256") != FROZEN_TRAINING_SHA256
        or sha256_file(training_path) != FROZEN_TRAINING_SHA256
    ):
        raise ValueError("Training CSV SHA-256 does not match the frozen G4/G5 partition")

    model = load_model(artifact_dir, expected_pipeline_sha256=FROZEN_PIPELINE_SHA256)
    if model.model_version != FROZEN_VERSION or model.decision_threshold != FROZEN_THRESHOLD:
        raise ValueError("Loaded model does not match the frozen version and threshold")
    return model, metadata


def predictor_vector(record):
    """Use exact CSV field strings in frozen feature order."""
    return tuple(record[name] for name in FEATURE_TYPES)


def score_metrics(actual, labels, scores):
    return {
        **binary_metrics(actual, labels),
        "roc_auc": float(roc_auc_score(actual, scores)),
        "average_precision": float(average_precision_score(actual, scores)),
    }


def overlap_subset(mask, actual, labels, scores):
    actual_subset = actual[mask]
    counts = class_distribution(actual_subset)
    return {
        "rows": len(actual_subset),
        **counts,
        "metrics": score_metrics(actual_subset, labels[mask], scores[mask])
        if all(counts.values()) else None,
    }


def evaluate_files(
    model: InferenceModel, training_path: Path, test_path: Path, *, batch_size: int = BATCH_SIZE,
) -> dict:
    """Score test rows in bounded batches and audit exact predictor overlap."""
    return _evaluate_rows(model, training_path, read_prediction_csv(test_path), batch_size=batch_size)


def _evaluate_rows(model, training_path, test_rows, *, batch_size=BATCH_SIZE):
    if model.decision_threshold != FROZEN_THRESHOLD:
        raise ValueError("Final evaluation requires the frozen 0.5 threshold")
    training_vectors = Counter(
        predictor_vector(row) for row in read_prediction_csv(training_path)
    )
    if not training_vectors:
        raise ValueError("Training CSV contains no rows to audit")

    testing_vectors = set()
    shared_vectors = set()
    shared_rows = []
    actual = []
    labels = []
    scores = []
    category_counts = Counter()
    detected_counts = Counter()
    for rows in batched(test_rows, batch_size):
        predictors = []
        targets = []
        for index, row in enumerate(rows, start=len(actual) + 1):
            label = row.get("label")
            if label not in {"0", "1"}:
                raise ValueError(f"Test record {index} has a missing or invalid binary label")
            targets.append(int(label))
            predictors.append({name: row[name] for name in FEATURE_TYPES})

        predictions = model.predict(predictors)
        for row, target, prediction in zip(rows, targets, predictions, strict=True):
            score = prediction["attack_probability"]
            label = prediction["label"]
            if not math.isfinite(score) or not 0 <= score <= 1 or label != int(score > FROZEN_THRESHOLD):
                raise ValueError("Prediction does not match the frozen decision rule")
            scores.append(score)
            labels.append(label)
            actual.append(target)
            vector = predictor_vector(row)
            testing_vectors.add(vector)
            shared = vector in training_vectors
            shared_rows.append(shared)
            if shared:
                shared_vectors.add(vector)
            if target == 1:
                category = row.get("attack_cat", "").strip() or "(missing)"
                category_counts[category] += 1
                detected_counts[category] += label

    actual_array = np.asarray(actual, dtype=int)
    labels_array = np.asarray(labels, dtype=int)
    scores_array = np.asarray(scores, dtype=float)
    class_counts = class_distribution(actual_array)
    if not all(class_counts.values()):
        raise ValueError("Test CSV must contain both normal and attack records")

    metrics = score_metrics(actual_array, labels_array, scores_array)
    mask = np.asarray(shared_rows, dtype=bool)
    return {
        "metrics": metrics,
        "test_class_counts": class_counts,
        "attack_categories": {
            category: {
                "support": support,
                "detected": int(detected_counts[category]),
                "missed": int(support - detected_counts[category]),
                "recall": detected_counts[category] / support,
            }
            for category, support in sorted(category_counts.items())
        },
        "normal": {
            "support": class_counts["normal"],
            "false_positives": metrics["confusion_matrix"][0][1],
            "false_positive_rate": metrics["false_positive_rate"],
        },
        "overlap": {
            "training_rows": sum(training_vectors.values()),
            "test_rows": len(actual),
            "training_unique_vectors": len(training_vectors),
            "test_unique_vectors": len(testing_vectors),
            "shared_vectors": len(shared_vectors),
            "shared_training_rows": sum(training_vectors[vector] for vector in shared_vectors),
            "shared_test_rows": int(mask.sum()),
            "shared_test": overlap_subset(mask, actual_array, labels_array, scores_array),
            "unshared_test": overlap_subset(~mask, actual_array, labels_array, scores_array),
        },
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args(argv)
    try:
        model, metadata = load_frozen_model(DEFAULT_ARTIFACT_DIR, TRAINING_CSV)
        with TEST_CSV.open("rb") as source, TemporaryFile() as snapshot:
            test_sha256 = file_digest(source, "sha256").hexdigest()
            if test_sha256 == FROZEN_TRAINING_SHA256:
                raise ValueError("Test CSV is identical to the training CSV")
            if test_sha256 != FROZEN_TEST_SHA256:
                raise ValueError("Test CSV SHA-256 does not match the official G10 test partition")
            source.seek(0)
            copyfileobj(source, snapshot)
            snapshot.seek(0)
            if file_digest(snapshot, "sha256").hexdigest() != test_sha256:
                raise ValueError("Test CSV changed before scoring")
            snapshot.seek(0)
            with TextIOWrapper(snapshot, encoding="utf-8-sig", newline="") as verified_test:
                report = _evaluate_rows(model, TRAINING_CSV, read_prediction_rows(verified_test))
        if (
            report["overlap"]["training_rows"] != EXPECTED_TRAINING_ROWS
            or report["overlap"]["test_rows"] != EXPECTED_TEST_ROWS
        ):
            raise ValueError("Row counts do not match the official prepared partitions")
        if sha256_file(TEST_CSV) != test_sha256 or sha256_file(TRAINING_CSV) != FROZEN_TRAINING_SHA256:
            raise ValueError("An evaluation CSV changed during the run")
    except (OSError, ValueError, csv.Error) as error:
        print(f"Final evaluation failed: {error}", file=sys.stderr)
        return 1

    print(json.dumps({
        "model_version": model.model_version,
        "decision_threshold": model.decision_threshold,
        "decision_rule": "attack_probability > decision_threshold",
        "pipeline_sha256": metadata["pipeline_sha256"],
        "feature_schema_sha256": FROZEN_SCHEMA_SHA256,
        "versions": metadata["versions"],
        "training_csv": {"file": TRAINING_CSV.name, "sha256": FROZEN_TRAINING_SHA256},
        "test_csv": {"file": TEST_CSV.name, "sha256": test_sha256},
        **report,
    }, indent=2, allow_nan=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
