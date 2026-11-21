"""Validate UNSW-NB15 predictor records and score them with a local model."""

import argparse
from collections.abc import Mapping
import csv
from dataclasses import dataclass
from hashlib import sha256
from importlib.metadata import version
import json
import math
from numbers import Integral, Real
from pathlib import Path
import pickle
import platform
import sys

import numpy as np
from sklearn.pipeline import Pipeline

from ml.inspect_dataset import DECIMAL, INTEGER, read_rows


MODEL_VERSION = "unsw-nb15-rf-v1"
ARTIFACT_FORMAT_VERSION = 1
DEFAULT_ARTIFACT_DIR = Path("artifacts") / MODEL_VERSION
DECISION_THRESHOLD = 0.5
CLASS_NAMES = {0: "normal", 1: "attack"}
OPTIONAL_METADATA_COLUMNS = {"id", "label", "attack_cat"}
FEATURE_TYPES = {
    "dur": "decimal",
    "proto": "text",
    "service": "text",
    "state": "text",
    "spkts": "integer",
    "dpkts": "integer",
    "sbytes": "integer",
    "dbytes": "integer",
    "rate": "decimal",
    "sttl": "integer",
    "dttl": "integer",
    "sload": "decimal",
    "dload": "decimal",
    "sloss": "integer",
    "dloss": "integer",
    "sinpkt": "decimal",
    "dinpkt": "decimal",
    "sjit": "decimal",
    "djit": "decimal",
    "swin": "integer",
    "stcpb": "integer",
    "dtcpb": "integer",
    "dwin": "integer",
    "tcprtt": "decimal",
    "synack": "decimal",
    "ackdat": "decimal",
    "smean": "integer",
    "dmean": "integer",
    "trans_depth": "integer",
    "response_body_len": "integer",
    "ct_srv_src": "integer",
    "ct_state_ttl": "integer",
    "ct_dst_ltm": "integer",
    "ct_src_dport_ltm": "integer",
    "ct_dst_sport_ltm": "integer",
    "ct_dst_src_ltm": "integer",
    "is_ftp_login": "integer_category",
    "ct_ftp_cmd": "integer",
    "ct_flw_http_mthd": "integer",
    "ct_src_ltm": "integer",
    "ct_srv_dst": "integer",
    "is_sm_ips_ports": "integer",
}


class InputValidationError(ValueError):
    """The prediction input does not match the expected feature schema."""


class ArtifactError(ValueError):
    """The configured local artifact cannot be used."""


def runtime_versions():
    dependencies = ("scikit-learn", "numpy", "scipy", "joblib", "threadpoolctl")
    return {"python": platform.python_version(), **{name: version(name) for name in dependencies}}


def feature_schema():
    return [{"name": name, "type": kind} for name, kind in FEATURE_TYPES.items()]


def validate_columns(columns):
    """Accept all predictors and only the three known optional metadata fields."""
    keys = set(columns)
    if any(not isinstance(name, str) or not name.strip() for name in keys):
        raise InputValidationError("column names must be nonempty strings")
    if len(keys) != len(columns):
        raise InputValidationError("duplicate column names")
    missing = set(FEATURE_TYPES) - keys
    unexpected = keys - set(FEATURE_TYPES) - OPTIONAL_METADATA_COLUMNS
    issues = []
    if missing:
        issues.append(f"missing columns: {', '.join(sorted(missing))}")
    if unexpected:
        issues.append(f"unexpected columns: {', '.join(sorted(unexpected))}")
    if issues:
        raise InputValidationError(" | ".join(issues))


def validated_value(value, kind):
    """Keep category values intact and parse numeric fields as finite numbers."""
    if value is None or (isinstance(value, str) and not value.strip()):
        raise InputValidationError("value is missing")
    if kind == "text":
        if not isinstance(value, str):
            raise InputValidationError("expected text")
        return value

    if isinstance(value, (bool, np.bool_)):
        raise InputValidationError("Booleans are not valid numeric values")
    if kind in {"integer", "integer_category"}:
        if not (isinstance(value, Integral) or (
            isinstance(value, str) and INTEGER.fullmatch(value.strip())
        )):
            raise InputValidationError("expected an integer")
        if kind == "integer_category":
            return str(value).strip()
    elif not (isinstance(value, Real) or (
        isinstance(value, str) and DECIMAL.fullmatch(value.strip())
    )):
        raise InputValidationError("expected a finite number")

    try:
        numeric = float(value)
    except (ValueError, OverflowError) as error:
        raise InputValidationError("expected a finite number") from error
    if not math.isfinite(numeric):
        raise InputValidationError("expected a finite number")
    return numeric


def validated_batch(records):
    """Validate every record before scoring and order fields for the pipeline."""
    try:
        records = iter(records)
    except TypeError as error:
        raise InputValidationError("provide an iterable of prediction records") from error
    rows = []
    for number, record in enumerate(records, start=1):
        if not isinstance(record, Mapping):
            raise InputValidationError(f"Record {number} must be a mapping of column names to values")
        try:
            validate_columns(record.keys())
        except InputValidationError as error:
            raise InputValidationError(f"Record {number}: {error}") from error
        row = []
        for name, kind in FEATURE_TYPES.items():
            try:
                row.append(validated_value(record[name], kind))
            except InputValidationError as error:
                raise InputValidationError(f"Record {number}, field {name!r}: {error}") from error
        rows.append(row)
    if not rows:
        raise InputValidationError("provide at least one prediction record")
    return np.asarray(rows, dtype=object)


@dataclass(frozen=True)
class InferenceModel:
    model_version: str
    decision_threshold: float
    _pipeline: Pipeline

    def predict(self, records):
        """Return one JSON-ready label and attack probability per input row."""
        batch = validated_batch(records)
        try:
            scores = self._pipeline.predict_proba(batch)[:, 1]
        except (ValueError, OverflowError) as error:
            raise InputValidationError(f"prediction batch could not be scored: {error}") from error
        if not np.isfinite(scores).all() or ((scores < 0) | (scores > 1)).any():
            raise ArtifactError("pipeline returned an invalid attack probability")
        predictions = []
        for score in scores:
            label = int(score > self.decision_threshold)
            predictions.append({
                "label": label,
                "classification": CLASS_NAMES[label],
                "attack_probability": float(score),
            })
        return predictions


def load_model(trusted_directory=DEFAULT_ARTIFACT_DIR):
    """Load a G5 package from a directory controlled by the local operator.

    Pickle deserializes Python objects and requires a trusted package source.
    The manifest digest checks consistency, rather than authenticating a source.
    """
    directory = Path(trusted_directory)
    try:
        metadata = json.loads((directory / "metadata.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise ArtifactError(f"Cannot read model metadata in {directory}: {error}") from error
    if not isinstance(metadata, dict) or metadata.get("format_version") != ARTIFACT_FORMAT_VERSION:
        raise ArtifactError("unsupported model package format")
    if (metadata.get("model_version") != MODEL_VERSION
        or metadata.get("feature_schema") != feature_schema()
        or metadata.get("decision_threshold") != DECISION_THRESHOLD):
        raise ArtifactError("model version, feature schema, or decision threshold is incompatible")
    if metadata.get("versions") != runtime_versions():
        raise ArtifactError("model package requires the runtime versions recorded in metadata.json")

    try:
        payload = (directory / "pipeline.pkl").read_bytes()
    except OSError as error:
        raise ArtifactError(f"Cannot read the local pipeline: {error}") from error
    if sha256(payload).hexdigest() != metadata.get("pipeline_sha256"):
        raise ArtifactError("pipeline digest does not match metadata.json")
    try:
        pipeline = pickle.loads(payload)
    except (pickle.UnpicklingError, EOFError, ImportError, AttributeError) as error:
        raise ArtifactError(f"Cannot load the local pipeline: {error}") from error
    if (not isinstance(pipeline, Pipeline)
        or getattr(pipeline, "n_features_in_", None) != len(FEATURE_TYPES)
        or list(getattr(pipeline, "classes_", [])) != [0, 1]):
        raise ArtifactError("pipeline does not expose the expected predictors and binary classes")
    return InferenceModel(metadata["model_version"], metadata["decision_threshold"], pipeline)


def read_prediction_csv(path):
    """Read strict CSV rows and reject malformed widths or duplicate headers."""
    with path.open(encoding="utf-8-sig", newline="") as file:
        reader = csv.reader(file, strict=True)
        try:
            header = next(reader, [])
            validate_columns(header)
            for row in read_rows(reader, header):
                yield dict(zip(header, row))
        except InputValidationError:
            raise
        except (ValueError, csv.Error) as error:
            raise InputValidationError(f"Invalid CSV near line {reader.line_num}: {error}") from error


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("csv_path", type=Path, help="CSV records to score; use the bundled synthetic example")
    args = parser.parse_args(argv)
    try:
        model = load_model()
        predictions = model.predict(read_prediction_csv(args.csv_path))
    except (OSError, ValueError, csv.Error) as error:
        print(f"Prediction failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps({
        "model_version": model.model_version,
        "decision_threshold": model.decision_threshold,
        "predictions": predictions,
    }, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
