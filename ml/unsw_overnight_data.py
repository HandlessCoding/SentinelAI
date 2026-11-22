"""Select only the pinned G32 fitting rows and keep ablated vectors together."""

from hashlib import sha256
from io import BytesIO
from itertools import combinations
from tempfile import NamedTemporaryFile
from pathlib import Path

import numpy as np
from sklearn.model_selection import StratifiedGroupKFold

from ml.inference import FEATURE_TYPES
from ml.run_baseline import TRAINING_CSV, TrainingData, class_distribution, load_training
from ml.run_unsw_development import TRAINING_SHA256, sha256_file
from ml.unsw_development_split import group_statistics, normalize_predictors


G32_ARCHIVE = Path("data/g32-ml-baselines/partitions.npz")
G32_ARCHIVE_SHA256 = "87436147eb1438cee52a562c02927f42533c5e4ad06b3854b2ac3a7b0fb2da88"
G32_ARCHIVE_BYTES = 270_408
SOURCE_BYTES = 32_293_018
SOURCE_ROWS = 175_341
FIT_ROWS = 100_199
FIT_CLASSES = {"normal": 32_002, "attack": 68_197}
FOLD_SEED = 32142
SMOKE_SEED = 32143
SMOKE_ROWS = 6_000
FOLD_COUNT = 5
TTL_FIELDS = {"sttl", "dttl", "ct_state_ttl"}
FEATURE_SETS = {
    "full": tuple(FEATURE_TYPES),
    "no_ttl": tuple(name for name in FEATURE_TYPES if name not in TTL_FIELDS),
    "no_context": tuple(name for name in FEATURE_TYPES
                        if name not in TTL_FIELDS and not name.startswith("ct_") and name != "is_sm_ips_ports"),
}


def read_g32_fit_indices(path):
    if path.stat().st_size != G32_ARCHIVE_BYTES:
        raise ValueError("The original G32 partition archive has an unexpected size")
    archive = path.read_bytes()
    if sha256(archive).hexdigest() != G32_ARCHIVE_SHA256:
        raise ValueError("The original G32 partition archive checksum does not match")
    with np.load(BytesIO(archive), allow_pickle=False) as partitions:
        indices = partitions["fit"]
    if (indices.shape != (FIT_ROWS,) or indices.dtype.kind not in "iu" or indices[0] < 0
            or indices[-1] >= SOURCE_ROWS or not np.all(indices[1:] > indices[:-1])):
        raise ValueError("The G32 fitting indices are invalid")
    return indices


def project_csv(source, indices, destination, *, expected_digest, expected_rows):
    """Hash the source as bytes and copy only selected physical CSV data lines."""
    source_hash = sha256()
    copied = 0
    rows = 0
    with NamedTemporaryFile(dir=destination.parent, delete=False) as staged:
        temporary = Path(staged.name)
        try:
            with source.open("rb") as stream:
                header = stream.readline()
                source_hash.update(header)
                staged.write(header)
                for index, raw_line in enumerate(stream):
                    source_hash.update(raw_line)
                    rows += 1
                    if copied < len(indices) and index == indices[copied]:
                        staged.write(raw_line)
                        copied += 1
            if source_hash.hexdigest() != expected_digest or rows != expected_rows or copied != len(indices):
                raise ValueError("Source checksum or verified fitting-row selection does not match")
            staged.close()
            digest = sha256_file(temporary)
            if destination.exists():
                if sha256_file(destination) != digest:
                    raise ValueError("The existing fitting-only snapshot does not match the verified projection")
            else:
                temporary.rename(destination)
            return digest
        finally:
            staged.close()
            temporary.unlink(missing_ok=True)


def load_overnight_data(directory, *, smoke=False):
    indices = read_g32_fit_indices(G32_ARCHIVE)
    if TRAINING_CSV.stat().st_size != SOURCE_BYTES:
        raise ValueError("The pinned training CSV has an unexpected size")
    projection = directory / "fit-only.csv"
    digest = project_csv(TRAINING_CSV, indices, projection,
                         expected_digest=TRAINING_SHA256, expected_rows=SOURCE_ROWS)
    data = load_training(projection)
    if data.columns != list(FEATURE_TYPES) or class_distribution(data.labels) != FIT_CLASSES:
        raise ValueError("The projected fitting partition has unexpected features or labels")
    if smoke:
        sample = np.sort(np.random.default_rng(SMOKE_SEED).choice(FIT_ROWS, SMOKE_ROWS, replace=False))
        data = TrainingData(data.columns, data.predictors[sample], data.labels[sample], data.groups[sample])
        indices = indices[sample]
    return normalize_predictors(data), {
        "g32_partition_archive_sha256": G32_ARCHIVE_SHA256, "source_csv_sha256": TRAINING_SHA256,
        "fitting_snapshot_sha256": digest, "selected_index_sha256": sha256(indices.astype("<i8").tobytes()).hexdigest(),
        "source_fitting_rows": FIT_ROWS, "used_rows": len(indices), "class_counts": class_distribution(data.labels),
    }


def column_positions(columns, feature_set):
    return [columns.index(name) for name in FEATURE_SETS[feature_set]]


def exact_groups(rows):
    identifiers = {}
    return np.fromiter((identifiers.setdefault(tuple(row), len(identifiers)) for row in rows), dtype=np.int64)


def plan_folds(data, *, minimum_class_rows=500):
    """Rotate five disjoint groups through evaluation and calibration roles."""
    groups = {"full": data.groups}
    for feature_set in ("no_ttl", "no_context"):
        groups[feature_set] = exact_groups(data.predictors[:, column_positions(data.columns, feature_set)])
    strictest = groups["no_context"]
    shuffled = np.random.default_rng(FOLD_SEED).permutation(int(strictest.max()) + 1)[strictest]
    folds = [holdout for _, holdout in StratifiedGroupKFold(n_splits=FOLD_COUNT).split(
        np.arange(len(data.labels)), data.labels, shuffled
    )]
    allocation, coverage, blockers = [], [], []
    full = np.arange(len(data.labels))
    if not np.array_equal(np.sort(np.concatenate(folds)), full):
        blockers.append("evaluation folds do not cover each fitting row once")
    for index, evaluation in enumerate(folds):
        calibration_index = (index + 1) % FOLD_COUNT
        calibration = folds[calibration_index]
        fitting = np.sort(np.concatenate([fold for i, fold in enumerate(folds) if i not in {index, calibration_index}]))
        roles = {"fit": fitting, "calibration": calibration, "evaluation": evaluation}
        allocation.append(roles)
        counts = {role: class_distribution(data.labels[indices]) for role, indices in roles.items()}
        overlap = {f"{left}/{right}": {
            name: int(np.intersect1d(keys[roles[left]], keys[roles[right]]).size) for name, keys in groups.items()
        } for left, right in combinations(roles, 2)}
        if any(any(pair.values()) for pair in overlap.values()):
            blockers.append(f"fold {index + 1} shares predictor groups")
        for role, classes in counts.items():
            if min(classes.values()) < minimum_class_rows:
                blockers.append(f"fold {index + 1} {role} lacks minimum class support")
            elif abs(classes["attack"] / sum(classes.values()) - float(np.mean(data.labels))) > 0.10:
                blockers.append(f"fold {index + 1} {role} deviates more than 10 percentage points in attack share")
        coverage.append({"fold": index + 1, "class_counts": counts, "pairwise_group_overlap": overlap})
    return allocation, {
        "seed": FOLD_SEED, "minimum_class_rows": minimum_class_rows, "folds": coverage,
        "groups": {name: group_statistics(data.labels, keys) for name, keys in groups.items()},
        "blockers": blockers,
    }
