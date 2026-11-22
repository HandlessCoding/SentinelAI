"""Prespecified, exact-vector-isolated splits for the UNSW training CSV."""

from itertools import combinations

import numpy as np
from sklearn.model_selection import StratifiedGroupKFold

from ml.run_baseline import CATEGORICAL_COLUMNS, TrainingData, class_distribution


SPLIT_SEED = 32042
FOLDS = 7
ROLES = ("fit", "calibration", "comparison", "final_validation")
MIN_CLASS_ROWS = 1_000
MAX_ATTACK_SHARE_DEVIATION = 0.075


def normalize_predictors(data):
    """Merge equivalent numeric spellings while keeping categorical tokens intact."""
    numeric_columns = [i for i, column in enumerate(data.columns) if column not in CATEGORICAL_COLUMNS]
    categorical_columns = [i for i, column in enumerate(data.columns) if column in CATEGORICAL_COLUMNS]
    normalized = data.predictors.copy()
    if any(not token or not token.strip() for token in normalized[:, categorical_columns].flat):
        raise ValueError("Training input contains an empty categorical value")
    numeric = normalized[:, numeric_columns].astype(np.float64)
    if not np.isfinite(numeric).all():
        raise ValueError("Training input contains a nonfinite numeric predictor")
    normalized[:, numeric_columns] = numeric
    group_ids = {}
    groups = np.empty(len(normalized), dtype=np.int64)
    for index, row in enumerate(normalized):
        groups[index] = group_ids.setdefault(tuple(row), len(group_ids))
    return TrainingData(data.columns, normalized, data.labels, groups)


def development_partitions(labels, groups):
    """Use a seeded group ordering for ties and assign complete folds to roles."""
    group_values, inverse = np.unique(groups, return_inverse=True)
    shuffled_ids = np.random.default_rng(SPLIT_SEED).permutation(group_values.size)[inverse]
    splitter = StratifiedGroupKFold(n_splits=FOLDS)
    folds = [validation for _, validation in splitter.split(np.arange(len(labels)), labels, shuffled_ids)]
    return dict(zip(ROLES, (np.sort(np.concatenate(folds[:4])), *folds[4:]), strict=True))


def group_statistics(labels, groups):
    unique, inverse = np.unique(groups, return_inverse=True)
    normal = np.bincount(inverse[labels == 0], minlength=len(unique))
    attack = np.bincount(inverse[labels == 1], minlength=len(unique))
    counts = normal + attack
    conflicting = (normal > 0) & (attack > 0)
    return {
        "groups": int(len(counts)),
        "duplicate_rows_beyond_first": int(counts.sum() - len(counts)),
        "repeated_groups": int((counts > 1).sum()),
        "largest_group_rows": int(counts.max(initial=0)),
        "conflicting_groups": int(conflicting.sum()),
        "rows_in_conflicting_groups": int(counts[conflicting].sum()),
        "minimum_errors_from_conflicts": int(np.minimum(normal, attack).sum()),
    }


def audit_partitions(labels, raw_groups, normalized_groups, partitions):
    """Require complete row coverage, disjoint groups and adequate class support."""
    if set(partitions) != set(ROLES):
        raise ValueError("The audit requires the four prescribed development roles")
    blockers = []
    if not np.array_equal(np.sort(np.concatenate(list(partitions.values()))), np.arange(len(labels))):
        blockers.append("rows are missing or assigned multiple times")
    full_attack_share = float(np.mean(labels))
    by_role = {}
    for role, indices in partitions.items():
        subset = labels[indices]
        classes = class_distribution(subset)
        attack_share = float(np.mean(subset)) if len(subset) else None
        by_role[role] = {"rows": len(indices), "class_counts": classes, "attack_share": attack_share,
                         "normalized_vectors": group_statistics(subset, normalized_groups[indices])}
        if min(classes.values()) < MIN_CLASS_ROWS:
            blockers.append(f"{role} lacks {MIN_CLASS_ROWS:,} rows of each class")
        if attack_share is not None and abs(attack_share - full_attack_share) > MAX_ATTACK_SHARE_DEVIATION:
            blockers.append(f"{role} attack share deviates by more than 7.5 percentage points")

    overlaps = {}
    for left, right in combinations(ROLES, 2):
        shared = {name: int(np.intersect1d(groups[partitions[left]], groups[partitions[right]]).size)
                  for name, groups in (("raw", raw_groups), ("normalized", normalized_groups))}
        overlaps[f"{left}/{right}"] = shared
        if any(shared.values()):
            blockers.append(f"{left} and {right} share predictor groups")
    return {
        "seed": SPLIT_SEED, "fold_count": FOLDS, "fold_allocation": dict(zip(ROLES, ([0, 1, 2, 3], [4], [5], [6]))),
        "minimum_rows_per_class_and_role": MIN_CLASS_ROWS,
        "maximum_attack_share_deviation": MAX_ATTACK_SHARE_DEVIATION,
        "class_counts": class_distribution(labels), "roles": by_role, "overlapping_groups": overlaps,
        "raw_vectors": group_statistics(labels, raw_groups),
        "normalized_vectors": group_statistics(labels, normalized_groups),
        "blockers": blockers, "training_allowed": not blockers,
    }
