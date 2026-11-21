"""Train the approved Random Forest and publish a local inference package."""

import argparse
import csv
from hashlib import file_digest, sha256
import json
from pathlib import Path
import pickle
import sys
from tempfile import TemporaryDirectory
from time import perf_counter

from threadpoolctl import threadpool_limits

from ml.inference import (
    ARTIFACT_FORMAT_VERSION,
    CLASS_NAMES,
    DECISION_THRESHOLD,
    DEFAULT_ARTIFACT_DIR,
    FEATURE_TYPES,
    MODEL_VERSION,
    feature_schema,
    runtime_versions,
)
from ml.run_baseline import CATEGORICAL_COLUMNS, TRAINING_CSV, class_distribution, load_training
from ml.run_model_comparison import forest_pipeline


def train_and_package(training_csv, destination):
    """Fit the G4 pipeline and publish a complete package without replacing one."""
    if destination.exists():
        raise FileExistsError(f"Model package already exists at {destination}")
    data = load_training(training_csv)
    if data.columns != list(FEATURE_TYPES):
        raise ValueError("Training CSV predictors do not match the versioned feature schema")
    classes = class_distribution(data.labels)
    if 0 in classes.values():
        raise ValueError("Model training requires both binary classes")
    with training_csv.open("rb") as file:
        training_digest = file_digest(file, "sha256").hexdigest()

    pipeline = forest_pipeline(data.columns)
    started = perf_counter()
    with threadpool_limits(limits=1):
        pipeline.fit(data.predictors, data.labels)
    fit_seconds = perf_counter() - started
    payload = pickle.dumps(pipeline, protocol=pickle.HIGHEST_PROTOCOL)

    classifier = pipeline.named_steps["classifier"]
    metadata = {
        "format_version": ARTIFACT_FORMAT_VERSION,
        "model_version": MODEL_VERSION,
        "model_type": type(classifier).__name__,
        "classes": CLASS_NAMES,
        "decision_threshold": DECISION_THRESHOLD,
        "decision_rule": "attack_probability > decision_threshold",
        "feature_schema": feature_schema(),
        "preprocessing": {
            "categorical_features": list(CATEGORICAL_COLUMNS),
            "categorical_encoder": "OneHotEncoder(handle_unknown='ignore')",
            "numeric_transformer": "StandardScaler",
        },
        "training": {
            "file": training_csv.name,
            "sha256": training_digest,
            "rows": len(data.labels),
            "class_counts": classes,
            "parameters": classifier.get_params(deep=False),
            "native_thread_limit": 1,
            "fit_seconds": fit_seconds,
        },
        "versions": runtime_versions(),
        "pipeline_bytes": len(payload),
        "pipeline_sha256": sha256(payload).hexdigest(),
    }

    destination.parent.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(prefix=".packaging-", dir=destination.parent) as temporary:
        staging = Path(temporary) / "package"
        staging.mkdir()
        (staging / "pipeline.pkl").write_bytes(payload)
        (staging / "metadata.json").write_text(
            json.dumps(metadata, indent=2) + "\n", encoding="utf-8"
        )
        staging.rename(destination)
    return metadata


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args(argv)
    try:
        metadata = train_and_package(TRAINING_CSV, DEFAULT_ARTIFACT_DIR)
    except (OSError, ValueError, csv.Error) as error:
        print(f"Model packaging failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps({
        "model_version": metadata["model_version"],
        "artifact_directory": str(DEFAULT_ARTIFACT_DIR),
        "training": metadata["training"],
        "pipeline_bytes": metadata["pipeline_bytes"],
        "pipeline_sha256": metadata["pipeline_sha256"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
