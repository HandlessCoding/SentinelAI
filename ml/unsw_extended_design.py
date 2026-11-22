"""Define the G32.2 candidate budget and isolate its locked internal challenge."""

from hashlib import sha256
from itertools import combinations, product

import numpy as np
from sklearn.model_selection import StratifiedGroupKFold

from ml.run_baseline import CATEGORICAL_COLUMNS, TrainingData, class_distribution
from ml.unsw_development_split import group_statistics
from ml.unsw_overnight_data import FEATURE_SETS as ORIGINAL_FEATURES, exact_groups
from ml.unsw_overnight_models import FOREST, HISTOGRAM, LOGISTIC


LOCK_SEED = 32207
DISCOVERY_SEEDS = (32242, 32267, 32291)
CHALLENGE_MODEL_SEED = 32311
SMOKE_FIXTURE_SEED = 32208
SHORTLIST_SIZE = 12
DISCOVERY_FOLDS = 5
ROLE_NAMES = ("fit", "probability", "threshold", "evaluation")
FEATURE_SETS = {
    "full": ORIGINAL_FEATURES["full"],
    "no_ttl": ORIGINAL_FEATURES["no_ttl"],
    "no_source_ttl": tuple(name for name in ORIGINAL_FEATURES["full"] if name not in {"sttl", "ct_state_ttl"}),
    "no_service_context": tuple(name for name in ORIGINAL_FEATURES["full"]
                                if name not in {"ct_srv_src", "ct_srv_dst", "ct_dst_src_ltm"}),
}


def paired_variants(recipe, family, params, extra=None):
    ablations = ["full", "no_ttl"]
    if extra is not None:
        ablations.append(extra)
    return [{"id": f"{recipe}-{ablation}", "recipe": recipe, "family": family, "feature_set": ablation,
             "parameters": params} for ablation in ablations]


def candidates(*, smoke=False):
    """Pair each estimator profile across full and TTL-free predictors."""
    result = []
    histogram_shapes = ((15, 20), (23, 32), (31, 20), (47, 28), (63, 12), (47, 55))
    histogram_paths = ((0.035, 300), (0.055, 235), (0.075, 170), (0.105, 125))
    penalties = (0.2, 1.5, 4.0, 9.0)
    weights = (None, {"0": 1.35, "1": 1.0}, {"0": 1.0, "1": 1.3}, "balanced")
    for index, ((leaves, minimum), (rate, rounds), profile) in enumerate(
        product(histogram_shapes, histogram_paths, (0, 1))
    ):
        phase = index // 8 + index // 2
        params = {**HISTOGRAM, "max_iter": rounds, "learning_rate": rate, "max_leaf_nodes": leaves,
                  "min_samples_leaf": minimum, "l2_regularization": penalties[(phase + 2 * profile) % 4],
                  "class_weight": weights[(phase + 3 * profile) % 4]}
        extra = ("no_source_ttl", "no_service_context")[(index // 4) % 2] if index % 4 == 1 else None
        result.extend(paired_variants(f"hgb-{index + 1:02}", "hgb", params, extra))

    forest_shapes = ((12, 384, 8), (16, 640, 5), (20, 1_024, 3), (24, 1_536, 3), (18, 896, 8))
    forest_draws = ((80, 0.60, "sqrt", None), (96, 0.78, 0.45, None), (112, 0.90, 0.65, None),
                    (128, 0.72, 0.35, "balanced_subsample"), (144, 0.85, 0.5, {"0": 1.4, "1": 1.0}))
    for index, ((depth, leaves, minimum), (trees, sample, features, weight)) in enumerate(product(forest_shapes, forest_draws)):
        params = {**FOREST, "n_estimators": trees, "max_depth": depth, "max_leaf_nodes": leaves,
                  "min_samples_leaf": minimum, "max_samples": sample, "max_features": features, "class_weight": weight}
        extra = ("no_source_ttl", "no_service_context")[(index // 3) % 2] if index in range(1, 25, 3) else None
        result.extend(paired_variants(f"rf-{index + 1:02}", "rf", params, extra))
    result.extend(paired_variants("rf-26", "rf", {**FOREST, "n_estimators": 160, "max_depth": 22,
                                  "max_leaf_nodes": 1_280, "min_samples_leaf": 4,
                                  "max_samples": 0.88, "max_features": 0.55}))

    for index, (regularization, weight) in enumerate(product((0.015, 0.06, 0.4, 2.25), (None, "balanced"))):
        result.extend(paired_variants(f"lr-{index + 1:02}", "lr", {**LOGISTIC, "C": regularization, "class_weight": weight}))

    result.sort(key=lambda row: (int(row["recipe"].split("-")[1]), ("hgb", "rf", "lr").index(row["family"])))
    if smoke:
        smoke_ids = {"hgb-01-full", "rf-01-no_ttl", "lr-01-full"}
        return [item for item in result if item["id"] in smoke_ids]
    return result


def synthetic_smoke_data():
    """Exercise the full staged workflow without exposing real challenge rows."""
    rng = np.random.default_rng(SMOKE_FIXTURE_SEED)
    columns = list(FEATURE_SETS["full"])
    numeric = rng.lognormal(1, 1, size=(2_400, len(columns)))
    rows = numeric.astype(object)
    vocabulary = (("tcp", "udp", "icmp"), ("-", "http", "dns"), ("FIN", "INT", "CON"), ("0", "1", "2", "4"))
    for name, values in zip(CATEGORICAL_COLUMNS, vocabulary, strict=True):
        rows[:, columns.index(name)] = rng.choice(values, len(rows))
    signal = np.log(numeric[:, 0]) + 0.7 * np.log(numeric[:, 4]) + rng.normal(size=len(rows))
    labels = (signal >= np.quantile(signal, 0.35)).astype(int)
    return TrainingData(columns, rows, labels, np.arange(len(rows)))


def positions(columns, features):
    return [columns.index(name) for name in features]


def feature_groups(data):
    common = [name for name in data.columns if all(name in columns for columns in FEATURE_SETS.values())]
    groups = {name: exact_groups(data.predictors[:, positions(data.columns, features)])
              for name, features in FEATURE_SETS.items()}
    groups["shared_projection"] = exact_groups(data.predictors[:, positions(data.columns, common)])
    return groups, common


def group_folds(labels, groups, count, seed):
    unique, inverse = np.unique(groups, return_inverse=True)
    shuffled = np.random.default_rng(seed).permutation(len(unique))[inverse]
    splitter = StratifiedGroupKFold(n_splits=count)
    return [test for _, test in splitter.split(np.arange(len(labels)), labels, shuffled)]


def audit_roles(labels, groups, roles, expected, minimum):
    counts = {role: class_distribution(labels[indices]) for role, indices in roles.items()}
    overlaps = {f"{left}/{right}": {
        name: int(np.intersect1d(keys[roles[left]], keys[roles[right]]).size) for name, keys in groups.items()
    } for left, right in combinations(roles, 2)}
    if not np.array_equal(np.sort(np.concatenate(list(roles.values()))), np.sort(expected)):
        raise ValueError("Roles must partition the declared cohort exactly once")
    if any(any(pair.values()) for pair in overlaps.values()):
        raise ValueError("Predictor groups cross role boundaries")
    prior = float(np.mean(labels[expected]))
    for role, classes in counts.items():
        if min(classes.values()) < minimum or abs(classes["attack"] / sum(classes.values()) - prior) > 0.10:
            raise ValueError(f"The {role} role failed class support or prevalence gates")
    return {"class_counts": counts, "overlapping_groups": overlaps, "indices_sha256": {
        role: sha256(indices.astype("<i8").tobytes()).hexdigest() for role, indices in roles.items()
    }}


def study_splits(data, *, smoke=False):
    """Keep challenge predictors and labels outside the discovery data object."""
    minimum = 20 if smoke else 500
    groups, common = feature_groups(data)
    original_rows = np.arange(len(data.labels))
    outer = group_folds(data.labels, groups["shared_projection"], 6, LOCK_SEED)
    discovery_indices = np.sort(np.concatenate(outer[1:]))
    challenge_roles = {"fit": np.sort(np.concatenate(outer[1:4])), "probability": outer[4],
                       "threshold": outer[5], "evaluation": outer[0]}
    challenge_audit = audit_roles(data.labels, groups, challenge_roles, original_rows, minimum)
    discovery_groups = {name: keys[discovery_indices] for name, keys in groups.items()}
    discovery = TrainingData(data.columns, data.predictors[discovery_indices], data.labels[discovery_indices],
                             discovery_groups["shared_projection"])
    rotations, role_audits = {}, {}
    for seed in DISCOVERY_SEEDS:
        folds = group_folds(discovery.labels, discovery.groups, DISCOVERY_FOLDS, seed)
        roles = []
        for i, evaluation in enumerate(folds):
            probability = (i + 1) % DISCOVERY_FOLDS
            threshold = (i + 2) % DISCOVERY_FOLDS
            fitting = np.sort(np.concatenate([fold for j, fold in enumerate(folds) if j not in {i, probability, threshold}]))
            roles.append({"fit": fitting, "probability": folds[probability],
                          "threshold": folds[threshold], "evaluation": evaluation})
        rotations[seed] = roles
        role_audits[str(seed)] = [audit_roles(discovery.labels, discovery_groups, role,
                                            np.arange(len(discovery.labels)), minimum) for role in roles]
    audit = {
        "challenge_seed": LOCK_SEED, "discovery_seeds": list(DISCOVERY_SEEDS), "minimum_class_rows": minimum,
        "shared_group_features": common, "challenge": challenge_audit, "rotations": role_audits,
        "groups": {name: group_statistics(data.labels, keys) for name, keys in groups.items()},
    }
    return discovery, rotations, challenge_roles, audit
