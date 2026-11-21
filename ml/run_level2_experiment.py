"""Bounded NF-ToN-IoT-v2 development experiment. No model files are saved."""

import argparse
from collections import Counter, defaultdict
import csv
from hashlib import file_digest
from io import TextIOWrapper
from ipaddress import IPv4Address
import json
from os import fstat
import platform
import sys
from time import perf_counter

import numpy as np
import sklearn
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from threadpoolctl import threadpool_limits

from ml.audit_level2_data import INPUT, file_identity, read_columns
from ml.compare_level2_features import RELEASE_ROWS, RELEASE_SHA256, sampled_rows
from ml.level2_feature_sets import FEATURE_SETS, FeatureSelector
from ml.level2_flow_schema import FlowValidationError
from ml.run_baseline import binary_metrics, class_distribution
from ml.run_model_comparison import default_metrics
from ml.run_threshold_analysis import BUDGETS, checked_splits, select_threshold


CANDIDATES = (
    "core", "core_packet_lengths", "core_tcp_flags", "core_lengths_flags",
    "core_ttl", "core_retransmissions",
)
FOCAL = "core_lengths_flags"
SEED = 42
CALIBRATION_SEED = 43
FOLDS = 3
MAX_ROWS = 250_000
MAX_FOLD_SHARE = 0.45
MIN_FOLD_SHARE = 0.20
MIN_CLASS_SHARE = 0.15
FOREST = {
    "n_estimators": 24, "max_depth": 10, "max_leaf_nodes": 256,
    "min_samples_leaf": 20, "max_samples": 0.67, "n_jobs": 1, "random_state": SEED,
}
TUPLE_COLUMNS = ("IPV4_SRC_ADDR", "L4_SRC_PORT", "IPV4_DST_ADDR", "L4_DST_PORT")


def exported_tuple(row, offsets, protocol):
    """Canonical reverse-invariant tuple proxy, including exported pseudo-port slots."""
    source, source_slot, target, target_slot = (row[i] for i in offsets)
    left = (int(IPv4Address(source)), int(source_slot))
    right = (int(IPv4Address(target)), int(target_slot))
    if not all(0 <= slot <= 65535 for _, slot in (left, right)):
        raise ValueError("Invalid exported tuple slot")
    return (protocol, *sorted((left, right)))


def connected_groups(vectors, tuples):
    """Compute the transitive closure of equal vectors or equal endpoint tuples."""
    parents, sizes = [], []
    first_vector, first_tuple = {}, {}

    def root(row):
        while parents[row] != row:
            parents[row] = parents[parents[row]]
            row = parents[row]
        return row

    def join(left, right):
        left, right = root(left), root(right)
        if left != right:
            if sizes[left] < sizes[right]:
                left, right = right, left
            parents[right] = left
            sizes[left] += sizes[right]

    for index, (vector, key) in enumerate(zip(vectors, tuples, strict=True)):
        parents.append(index)
        sizes.append(1)
        join(index, first_vector.setdefault(vector, index))
        join(index, first_tuple.setdefault(key, index))
    return np.array([root(row) for row in range(len(parents))])


def group_support(labels, groups):
    _, inverse, counts = np.unique(groups, return_inverse=True, return_counts=True)
    attacks = np.bincount(inverse[labels == 1], minlength=len(counts))
    biggest = int(np.argmax(counts))
    return {
        "groups": len(counts), "mixed_groups": int(np.sum((attacks > 0) & (attacks < counts))),
        "singletons": int(np.sum(counts == 1)),
        "top_sizes": sorted(counts.tolist(), reverse=True)[:5],
        "largest": {"rows": int(counts[biggest]), "attack": int(attacks[biggest]),
                    "normal": int(counts[biggest] - attacks[biggest])},
    }


def feasibility(labels, components):
    support = group_support(labels, components)
    largest = support["largest"]
    reasons = []
    if support["groups"] < FOLDS:
        reasons.append("fewer components than folds")
    if largest["rows"] > MAX_FOLD_SHARE * len(labels):
        reasons.append("largest component exceeds maximum fold size")
    for name, total in class_distribution(labels).items():
        if total - largest[name] < (FOLDS - 1) * MIN_CLASS_SHARE * total:
            reasons.append(f"remaining components cannot meet {name} support")
    splits = []
    if not reasons:
        try:
            splits = list(checked_splits(labels, components, FOLDS, SEED))
        except ValueError as error:
            reasons.append(str(error))
        for _, val, detail in splits:
            if not MIN_FOLD_SHARE <= len(val) / len(labels) <= MAX_FOLD_SHARE:
                reasons.append("candidate fold size is outside the prespecified band")
            if any(detail["validation_classes"][name] < total * MIN_CLASS_SHARE
                   for name, total in class_distribution(labels).items()):
                reasons.append("candidate fold misses the prespecified minimum class support")
    return {**support, "row_feasible": not reasons, "reasons": sorted(set(reasons)),
            "candidate_folds": [detail for _, _, detail in splits]}, splits


def prepare_sample(rows, columns, *, audit_only):
    names = ("core",) if audit_only else CANDIDATES
    selector = FeatureSelector(names).bind(columns)
    label_pos, category_pos = columns.index("Label"), columns.index("Attack")
    tuple_offsets = [columns.index(name) for name in TUPLE_COLUMNS]
    labels, categories, tuples = [], [], []
    keys = {name: [] for name in names}
    features = {name: [] for name in names}
    for row in rows:
        prepared = selector.prepare(row)
        if any(isinstance(vector, FlowValidationError) for vector in prepared.values()):
            raise ValueError("Feature validation failed on the common sample")
        if row[label_pos] not in ("0", "1"):
            raise ValueError("Invalid binary label")
        labels.append(int(row[label_pos]))
        categories.append(row[category_pos].casefold())
        tuples.append(exported_tuple(row, tuple_offsets, prepared["core"][0]))
        for name, values in prepared.items():
            keys[name].append(FEATURE_SETS[name].pack(values))
            if not audit_only:
                if any(v is not None and v > (1 << 53) for v in values):
                    raise ValueError("A predictor would lose integer precision in the model matrix")
                features[name].append(tuple(-1 if v is None else v for v in values))
    return np.array(labels), np.array(categories), tuples, keys, {
        name: np.asarray(values, dtype=np.float64) for name, values in features.items()
    }


def build_model(name, columns):
    categorical = [i for i, col in enumerate(columns) if col == "protocol" or col.endswith("_flags")]
    numerical = [i for i in range(len(columns)) if i not in categorical]
    logistic = name == "logistic"
    estimator = (LogisticRegression(solver="liblinear", max_iter=500, random_state=SEED)
                 if logistic else RandomForestClassifier(**FOREST))
    preprocessor = ColumnTransformer([
        ("categorical", OneHotEncoder(handle_unknown="ignore", sparse_output=False), categorical),
        ("numeric", StandardScaler() if logistic else "passthrough", numerical),
    ])
    return Pipeline([("prepare", preprocessor), ("model", estimator)])


def ambiguous_mask(keys, labels):
    masks = defaultdict(int)
    for key, label in zip(keys, labels, strict=True):
        masks[key] |= 1 << int(label)
    return np.array([masks[key] == 3 for key in keys])


def subgroup_metrics(labels, categories, predicted, ambiguous):
    slices = {"ambiguous": ambiguous, "single_label": ~ambiguous}
    return {
        "ambiguity": {
            name: {**class_distribution(labels[mask]), **binary_metrics(labels[mask], predicted[mask])}
            for name, mask in slices.items() if mask.any()
        },
        "categories": {
            name: {"support": int(mask.sum()), "caught": int(predicted[mask].sum()),
                   "recall": float(predicted[mask].mean())}
            for name in sorted(set(categories[labels == 1]))
            if (mask := (categories == name) & (labels == 1)).any()
        },
    }


def fold_design(labels, groups, tuples, core):
    folds = []
    for outer, val, detail in checked_splits(labels, groups, FOLDS, SEED):
        fit_rel, cal_rel, _ = next(checked_splits(labels[outer], groups[outer], FOLDS, CALIBRATION_SEED))
        fit, calibration = outer[fit_rel], outer[cal_rel]
        split_vectors = {core[i] for i in val}
        if split_vectors.intersection(core[i] for i in outer):
            raise RuntimeError("Exact core vectors crossed the validation boundary")
        train_tuples = {tuples[i] for i in outer}
        shared = train_tuples.intersection(tuples[i] for i in val)
        detail.update(
            fit_classes=class_distribution(labels[fit]),
            calibration_classes=class_distribution(labels[calibration]),
            shared_exported_tuples=len(shared),
            validation_rows_with_shared_tuple=sum(tuples[i] in shared for i in val),
        )
        folds.append((fit, calibration, val, detail))
    return folds


def evaluate(labels, categories, keys, features, folds):
    results = {}
    for candidate in CANDIDATES:
        print(f"Evaluating {candidate}", file=sys.stderr, flush=True)
        ambiguous = ambiguous_mask(keys[candidate], labels)
        results[candidate] = {}
        for name in ("logistic", "forest"):
            scores = np.empty(len(labels))
            fold_reports = []
            decisions = {budget: np.zeros(len(labels), dtype=bool) for budget in BUDGETS}
            matrix = features[candidate]
            for fit, calibration, validation, _ in folds:
                overlap = set(keys[candidate][i] for i in validation)
                if overlap.intersection(keys[candidate][i] for i in np.r_[fit, calibration]):
                    raise RuntimeError("Candidate vectors crossed the validation boundary")
                model = build_model(name, FEATURE_SETS[candidate].columns)
                started = perf_counter()
                model.fit(matrix[fit], labels[fit])
                fit_seconds = perf_counter() - started
                thresholds = {}
                if candidate == FOCAL:
                    cal_scores = model.predict_proba(matrix[calibration])[:, 1]
                    for budget, cap in BUDGETS.items():
                        thresholds[budget] = select_threshold(labels[calibration], cal_scores, cap)
                scores[validation] = model.predict_proba(matrix[validation])[:, 1]
                for budget, threshold in thresholds.items():
                    if threshold is not None:
                        decisions[budget][validation] = scores[validation] >= threshold["threshold"]
                        metrics = binary_metrics(labels[validation], decisions[budget][validation])
                        threshold["validation"] = metrics
                        threshold["budget_met"] = metrics["false_positive_rate"] <= BUDGETS[budget]
                fold_reports.append({
                    "default": default_metrics(labels[validation], scores[validation]),
                    "fit_seconds": round(fit_seconds, 4), "thresholds": thresholds,
                })
            tuned = {
                budget: (binary_metrics(labels, decisions[budget])
                         if all(fold["thresholds"][budget] is not None for fold in fold_reports) else None)
                for budget in BUDGETS
            } if candidate == FOCAL else {}
            results[candidate][name] = {
                "default": default_metrics(labels, scores), "folds": fold_reports, "tuned": tuned,
                **subgroup_metrics(labels, categories, scores > 0.5, ambiguous),
            }
    return results


def run_release(rows, *, audit_only=False):
    started = perf_counter()
    with INPUT.open("rb") as source:
        original = fstat(source.fileno())
        sha256 = file_digest(source, "sha256").hexdigest()
        if sha256 != RELEASE_SHA256:
            raise ValueError("Input does not match the approved development release")
        source.seek(0)
        with TextIOWrapper(source, encoding="utf-8-sig", newline="") as decoded:
            columns = read_columns(csv.reader(decoded, strict=True))
            data = prepare_sample(sampled_rows(decoded, RELEASE_ROWS, rows, SEED), columns, audit_only=audit_only)
            if file_identity(fstat(source.fileno())) != file_identity(original):
                raise ValueError("Source changed during sample loading")
    if file_identity(INPUT.stat()) != file_identity(original):
        raise ValueError("Source path changed during sample loading")
    labels, categories, tuples, keys, features = data
    core = keys["core"]
    components = connected_groups(core, tuples)
    graph, _ = feasibility(labels, components)
    _, vectors = np.unique(core, return_inverse=True)
    report = {
        "records": len(labels), "classes": class_distribution(labels),
        "categories": dict(Counter(categories)), "sample_seed": SEED, "sha256": sha256,
        "graph": graph, "distinct_tuples": len(set(tuples)), "core_vectors": group_support(labels, vectors),
        "capture_overlap": None, "session_overlap": None,
        "versions": {"python": platform.python_version(), "numpy": np.__version__, "sklearn": sklearn.__version__},
        "forest": FOREST,
    }
    if not audit_only:
        groups = components if graph["row_feasible"] else vectors
        folds = fold_design(labels, groups, tuples, core)
        report.update(
            scope="exploratory development pilot", split="components" if graph["row_feasible"] else "core vectors only",
            folds=[detail for _, _, _, detail in folds], models=evaluate(labels, categories, keys, features, folds),
        )
    report["seconds"] = round(perf_counter() - started, 3)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rows", type=int, required=True)
    parser.add_argument("--audit-only", action="store_true")
    args = parser.parse_args(argv)
    if not 1 <= args.rows <= MAX_ROWS:
        parser.error(f"Sample size must be from 1 to {MAX_ROWS:,}")
    with threadpool_limits(limits=1):
        report = run_release(args.rows, audit_only=args.audit_only)
    print(json.dumps(report, indent=2, allow_nan=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
