"""Plan Level 2 development folds from sorted, counted feature vectors.

Vector isolation is observable from canonical inputs. Capture isolation
requires a verified provenance mapping for every included row.
"""

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from functools import lru_cache
from hashlib import blake2b, sha256


@dataclass(frozen=True, slots=True)
class ClassSupport:
    benign: int = 0
    attack: int = 0
    vectors: int = 0

    @property
    def rows(self) -> int:
        return self.benign + self.attack

    def __add__(self, other: "ClassSupport") -> "ClassSupport":
        return ClassSupport(
            self.benign + other.benign,
            self.attack + other.attack,
            self.vectors + other.vectors,
        )

    def __sub__(self, other: "ClassSupport") -> "ClassSupport":
        return ClassSupport(
            self.benign - other.benign,
            self.attack - other.attack,
            self.vectors - other.vectors,
        )


@dataclass(frozen=True, slots=True)
class VectorGroup:
    """Counts for one canonical vector, with optional externally resolved IDs.

    When supplying provenance, include every capture the vector occurs in.
    Supply `session_ids` only as a complete list for the rows in this
    vector group. Namespace identifiers by source where necessary.
    """

    key: bytes
    benign: int
    attack: int
    capture_ids: tuple[str, ...] = ()
    session_ids: tuple[str, ...] = ()

    @property
    def support(self) -> ClassSupport:
        return ClassSupport(self.benign, self.attack, 1)


@dataclass(frozen=True, slots=True)
class FoldSupport:
    validation_fold: int
    training: ClassSupport
    validation: ClassSupport
    has_class_support: bool


@dataclass(frozen=True, slots=True)
class SplitPlan:
    """Fold counts and overlap measured at the available provenance levels.

    `None` means unobservable overlap. A zero for capture IDs represents
    the supplied provenance mapping. Independence also depends on the
    coverage and lineage that the mapping documents.
    """

    seed: int
    folds: tuple[FoldSupport, ...]
    largest_vector_rows: int
    largest_component_rows: int
    exact_vector_overlap: int = 0
    capture_overlap: int | None = None
    session_overlap: int | None = None
    provenance_reference: str | None = None
    capture_folds: dict[str, int] = field(default_factory=dict)
    session_folds: dict[str, int] = field(default_factory=dict)


def _validate_fold_settings(fold_count: int, seed: int) -> None:
    if type(fold_count) is not int or fold_count < 2:
        raise ValueError("fold_count must be an integer of at least two")
    if type(seed) is not int:
        raise ValueError("seed must be an integer")


def _validate_key(key: bytes) -> None:
    if not isinstance(key, bytes) or not key:
        raise ValueError("A canonical vector key must be nonempty bytes")


@lru_cache(maxsize=32)
def _digest_key(seed: int) -> bytes:
    return sha256(f"sentinelai-level2-vector-fold-v1:{seed}".encode("ascii")).digest()


def fold_for_vector(key: bytes, fold_count: int = 3, seed: int = 42) -> int:
    """Assign equal canonical keys to the same fold without storing rows."""
    _validate_fold_settings(fold_count, seed)
    _validate_key(key)
    digest = blake2b(key, digest_size=8, key=_digest_key(seed)).digest()
    return int.from_bytes(digest, "big") % fold_count


def _sorted_groups(groups: Iterable[VectorGroup]) -> Iterable[VectorGroup]:
    previous_key = None
    for group in groups:
        _validate_key(group.key)
        if previous_key is not None and group.key <= previous_key:
            raise ValueError("Supply one counted record per vector in ascending key order")
        if any(type(count) is not int or count < 0 for count in (group.benign, group.attack)):
            raise ValueError("Class counts must be nonnegative integers")
        if group.benign + group.attack == 0:
            raise ValueError("A counted vector must represent at least one row")
        yield group
        previous_key = group.key


def _fold_support(
    counts: list[ClassSupport], minimum_class_rows: int, validation_folds: Iterable[int]
) -> tuple[FoldSupport, ...]:
    if type(minimum_class_rows) is not int or minimum_class_rows < 1:
        raise ValueError("minimum_class_rows must be a positive integer")
    total = sum(counts, start=ClassSupport())
    if total.rows == 0:
        raise ValueError("At least one counted vector is required")
    result = []
    for fold in validation_folds:
        validation = counts[fold]
        training = total - validation
        supported = min(validation.benign, validation.attack, training.benign, training.attack)
        result.append(FoldSupport(fold, training, validation, supported >= minimum_class_rows))
    return tuple(result)


def plan_vector_folds(
    groups: Iterable[VectorGroup], fold_count: int = 3, seed: int = 42, minimum_class_rows: int = 1
) -> SplitPlan:
    """Stream sorted unique vector counts into reproducible diagnostic folds.

    Memory scales with the number of folds. The hash assignment preserves
    exact vector groups and leaves capture and session overlap unknown.
    Check class support and fold sizes before interpreting a partition.
    """
    _validate_fold_settings(fold_count, seed)
    counts = [ClassSupport() for _ in range(fold_count)]
    largest = 0
    for group in _sorted_groups(groups):
        fold = fold_for_vector(group.key, fold_count, seed)
        support = group.support
        counts[fold] = counts[fold] + support
        largest = max(largest, support.rows)
    return SplitPlan(seed, _fold_support(counts, minimum_class_rows, range(fold_count)), largest, largest)


_Node = tuple[str, str]


class _ProvenanceComponents:
    """Union verified capture/session nodes that share an exact vector."""

    def __init__(self) -> None:
        self.parents: dict[_Node, _Node] = {}
        self.sizes: dict[_Node, int] = {}
        self.support: dict[_Node, ClassSupport] = {}

    def root(self, node: _Node) -> _Node:
        while node != self.parents[node]:
            self.parents[node] = self.parents[self.parents[node]]
            node = self.parents[node]
        return node

    def add(self, node: _Node) -> _Node:
        if node not in self.parents:
            self.parents[node] = node
            self.sizes[node] = 1
            self.support[node] = ClassSupport()
        return self.root(node)

    def join(self, left: _Node, right: _Node) -> _Node:
        if left == right:
            return left
        if self.sizes[left] < self.sizes[right]:
            left, right = right, left
        self.parents[right] = left
        self.sizes[left] += self.sizes.pop(right)
        self.support[left] = self.support[left] + self.support.pop(right)
        return left


def _collect_provenance(
    groups: Iterable[VectorGroup], provenance_reference: str
) -> tuple[_ProvenanceComponents, int, bool]:
    if not isinstance(provenance_reference, str) or not provenance_reference.strip():
        raise ValueError("Provide a reference to the verified capture provenance")
    components = _ProvenanceComponents()
    largest = 0
    complete_sessions = True
    for group in _sorted_groups(groups):
        if not group.capture_ids:
            raise ValueError("Verified capture IDs must cover every vector group")
        nodes = [("capture", capture) for capture in group.capture_ids]
        nodes.extend(("session", session) for session in group.session_ids)
        if any(not isinstance(name, str) or not name.strip() for _, name in nodes):
            raise ValueError("Provenance IDs must be nonempty strings")
        root = components.add(nodes[0])
        for node in nodes[1:]:
            root = components.join(root, components.add(node))
        support = group.support
        components.support[root] = components.support[root] + support
        largest = max(largest, support.rows)
        complete_sessions = complete_sessions and bool(group.session_ids)
    if not components.support:
        raise ValueError("At least one counted vector is required")
    return components, largest, complete_sessions


def _capture_ids(components: _ProvenanceComponents) -> dict[_Node, list[str]]:
    by_root: defaultdict[_Node, list[str]] = defaultdict(list)
    for node in sorted(components.parents):
        if node[0] == "capture":
            by_root[components.root(node)].append(node[1])
    return dict(by_root)


def _provenance_plan(
    components: _ProvenanceComponents,
    assignments: dict[_Node, int],
    fold_count: int,
    validation_folds: Iterable[int],
    seed: int,
    minimum_class_rows: int,
    largest: int,
    provenance_reference: str,
    complete_sessions: bool,
) -> SplitPlan:
    counts = [ClassSupport() for _ in range(fold_count)]
    for root, support in components.support.items():
        fold = assignments[root]
        counts[fold] = counts[fold] + support
    maps: dict[str, dict[str, int]] = {"capture": {}, "session": {}}
    for node in sorted(components.parents):
        kind, name = node
        maps[kind][name] = assignments[components.root(node)]
    return SplitPlan(
        seed,
        _fold_support(counts, minimum_class_rows, validation_folds),
        largest,
        max(support.rows for support in components.support.values()),
        capture_overlap=0,
        session_overlap=0 if complete_sessions else None,
        provenance_reference=provenance_reference,
        capture_folds=maps["capture"],
        session_folds=maps["session"],
    )


def plan_capture_folds(
    groups: Iterable[VectorGroup],
    *,
    provenance_reference: str,
    fold_count: int = 3,
    seed: int = 42,
    minimum_class_rows: int = 1,
) -> SplitPlan:
    """Keep verified captures, supplied sessions, and exact vectors together.

    Assign largest connected components first to folds with the fewest rows.
    Use the smallest capture ID as a stable component identifier. Memory
    scales with the number of distinct provenance IDs and folds.
    """
    _validate_fold_settings(fold_count, seed)
    components, largest, complete_sessions = _collect_provenance(groups, provenance_reference)
    captures = _capture_ids(components)
    ordered = sorted(components.support, key=lambda root: (-components.support[root].rows, captures[root][0]))
    counts = [0] * fold_count
    assignments = {}
    for root in ordered:
        preferred = fold_for_vector(captures[root][0].encode("utf-8"), fold_count, seed)
        fold = min(range(fold_count), key=lambda index: (counts[index], (index - preferred) % fold_count))
        assignments[root] = fold
        counts[fold] += components.support[root].rows
    return _provenance_plan(
        components, assignments, fold_count, range(fold_count), seed,
        minimum_class_rows, largest, provenance_reference, complete_sessions,
    )


def plan_capture_holdout(
    groups: Iterable[VectorGroup],
    *,
    validation_captures: Iterable[str],
    provenance_reference: str,
    minimum_class_rows: int = 1,
) -> SplitPlan:
    """Evaluate feasibility of holding out named development captures.

    Fold 0 is development training, and fold 1 is validation. Refuse a
    boundary linked by any exact vector or verified session. This function
    takes development metadata and counts supplied by its caller.
    """
    reserved = set(validation_captures)
    if not reserved:
        raise ValueError("Choose at least one development capture to hold out")
    components, largest, complete_sessions = _collect_provenance(groups, provenance_reference)
    captures = _capture_ids(components)
    known = {capture for group in captures.values() for capture in group}
    if not reserved <= known:
        raise ValueError("A reserved capture is absent from the verified provenance")
    if reserved == known:
        raise ValueError("Capture holdout must leave at least one development training capture")
    assignments = {}
    for root, group in captures.items():
        held_out = sum(capture in reserved for capture in group)
        if 0 < held_out < len(group):
            raise ValueError("The holdout boundary shares an exact vector or a verified session")
        assignments[root] = int(held_out > 0)
    return _provenance_plan(
        components, assignments, 2, (1,), 0,
        minimum_class_rows, largest, provenance_reference, complete_sessions,
    )
