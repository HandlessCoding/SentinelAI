"""Count exact duplicate groups by sorting bounded chunks on local disk."""

from collections.abc import Callable, Iterable, Iterator
from contextlib import ExitStack
from dataclasses import dataclass
from heapq import merge
from operator import itemgetter
from pathlib import Path
from struct import Struct
from tempfile import TemporaryDirectory
from typing import BinaryIO


# Each run record stores the key width, total rows, normal rows, and attack rows.
_RUN_HEADER = Struct("<IQQQ")
_IO_BUFFER_BYTES = 256 * 1024
_MAX_KEY_BYTES = 1024 * 1024
# This allowance covers Python dictionary slots, counts, and a sorted key list.
_ESTIMATED_ENTRY_OVERHEAD = 192

CountedKey = tuple[bytes, int, int, int]


@dataclass(frozen=True)
class GroupSummary:
    """Summarize groups and the number of observations represented by them.

    Duplicate occurrences omit the first observation in each group. Duplicate
    rows include every observation in a group of size two or more. Conflicting
    rows include every observation in a group with both known binary labels.
    """

    rows: int
    distinct_groups: int
    duplicate_occurrences: int
    duplicate_groups: int
    duplicate_rows: int
    conflicting_groups: int
    conflicting_rows: int
    conflicting_normal_rows: int
    conflicting_attack_rows: int
    max_group_size: int


def _run_records(stream: BinaryIO) -> Iterator[CountedKey]:
    while header := stream.read(_RUN_HEADER.size):
        if len(header) != _RUN_HEADER.size:
            raise OSError("Truncated group-count run header")
        width, total, normal, attack = _RUN_HEADER.unpack(header)
        if width > _MAX_KEY_BYTES:
            raise OSError("Invalid group-count run key width")
        key = stream.read(width)
        if len(key) != width:
            raise OSError("Truncated group-count run key")
        yield key, total, normal, attack


def _combine_runs(paths: Iterable[Path]) -> Iterator[CountedKey]:
    """Merge sorted runs without holding their keys or groups in memory."""
    with ExitStack() as stack:
        streams = (
            stack.enter_context(path.open("rb", buffering=_IO_BUFFER_BYTES))
            for path in paths
        )
        sorted_counts = merge(*(_run_records(stream) for stream in streams), key=itemgetter(0))
        previous_key = None
        total = normal = attack = 0
        for key, rows, normal_rows, attack_rows in sorted_counts:
            if previous_key is not None and key != previous_key:
                yield previous_key, total, normal, attack
                total = normal = attack = 0
            previous_key = key
            total += rows
            normal += normal_rows
            attack += attack_rows

        if previous_key is not None:
            yield previous_key, total, normal, attack


def _summarize(
    groups: Iterable[CountedKey], on_group: Callable[[CountedKey], None] | None
) -> GroupSummary:
    rows = distinct_groups = duplicate_groups = duplicate_rows = 0
    conflicting_groups = conflicting_rows = conflicting_normal_rows = conflicting_attack_rows = 0
    max_group_size = 0
    for group in groups:
        if on_group is not None:
            on_group(group)
        _, total, normal, attack = group
        rows += total
        distinct_groups += 1
        max_group_size = max(max_group_size, total)
        if total > 1:
            duplicate_groups += 1
            duplicate_rows += total
        if normal and attack:
            conflicting_groups += 1
            conflicting_rows += total
            conflicting_normal_rows += normal
            conflicting_attack_rows += attack

    return GroupSummary(
        rows=rows,
        distinct_groups=distinct_groups,
        duplicate_occurrences=rows - distinct_groups,
        duplicate_groups=duplicate_groups,
        duplicate_rows=duplicate_rows,
        conflicting_groups=conflicting_groups,
        conflicting_rows=conflicting_rows,
        conflicting_normal_rows=conflicting_normal_rows,
        conflicting_attack_rows=conflicting_attack_rows,
        max_group_size=max_group_size,
    )


class ExactGroupCounter:
    """Accumulate exact keys and optional binary labels using local scratch runs.

    Use the counter in a context manager. Each caller supplies an unambiguous
    bytes key. Sorted runs store the complete keys so byte equality determines
    identity, including across chunks. Chunk budgeting estimates retained
    Python memory. Merges open at most the configured number of run readers.
    """

    def __init__(
        self,
        scratch_parent: Path,
        *,
        max_chunk_bytes: int = 32 * 1024 * 1024,
        merge_fan_in: int = 32,
    ) -> None:
        if max_chunk_bytes < _ESTIMATED_ENTRY_OVERHEAD:
            raise ValueError("Group-count chunk budget is too small")
        if not 2 <= merge_fan_in <= 64:
            raise ValueError("Group-count merge fan-in must be between 2 and 64")
        self._scratch_parent = scratch_parent
        self._max_chunk_bytes = max_chunk_bytes
        self._merge_fan_in = merge_fan_in
        self._temporary: TemporaryDirectory[str] | None = None
        self._chunk: dict[bytes, tuple[int, int, int]] = {}
        self._chunk_bytes = 0
        self._levels: list[list[Path]] = []
        self._next_id = 0
        self._result: GroupSummary | None = None
        self._closed = False

    def __enter__(self) -> "ExactGroupCounter":
        if self._temporary is not None or self._closed:
            raise RuntimeError("Group counters are single-use")
        self._temporary = TemporaryDirectory(prefix="level2-groups-", dir=self._scratch_parent)
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        if self._temporary is not None:
            self._temporary.cleanup()
            self._temporary = None
        self._chunk.clear()
        self._levels.clear()
        self._chunk_bytes = 0
        self._closed = True

    def add(self, key: bytes, label: int | None = None) -> None:
        """Count one occurrence. Only known binary labels contribute to a conflict."""
        self._require_open()
        if self._result is not None:
            raise RuntimeError("Group counter is already finalized")
        if not isinstance(key, bytes):
            raise TypeError("Group key must be bytes")
        if label is not None and (type(label) is not int or label not in (0, 1)):
            raise ValueError("Group label must be 0, 1, or None")

        existing = self._chunk.get(key)
        if existing is None:
            if len(key) > _MAX_KEY_BYTES:
                raise ValueError("Group key exceeds the 1 MiB audit limit")
            entry_bytes = len(key) + _ESTIMATED_ENTRY_OVERHEAD
            if entry_bytes > self._max_chunk_bytes:
                raise ValueError("Group key exceeds the group-count chunk budget")
            if self._chunk_bytes + entry_bytes > self._max_chunk_bytes:
                self._flush()
            self._chunk_bytes += entry_bytes
            existing = (0, 0, 0)
        total, normal, attack = existing
        self._chunk[key] = (total + 1, normal + (label == 0), attack + (label == 1))

    def finish(self, *, on_group: Callable[[CountedKey], None] | None = None) -> GroupSummary:
        """Return the summary and release keys, visiting each group on the first call."""
        self._require_open()
        if self._result is not None:
            return self._result

        if self._levels:
            self._flush()
            runs = [path for level in self._levels for path in level]
            while len(runs) > self._merge_fan_in:
                compacted = self._compact(runs[:self._merge_fan_in])
                runs = runs[self._merge_fan_in:] + [compacted]
            self._result = _summarize(_combine_runs(runs), on_group)
            for path in runs:
                path.unlink()
            self._levels.clear()
        else:
            groups = ((key, *counts) for key, counts in self._chunk.items())
            self._result = _summarize(groups, on_group)
            self._chunk.clear()
            self._chunk_bytes = 0
        return self._result

    def _require_open(self) -> TemporaryDirectory[str]:
        if self._temporary is None:
            raise RuntimeError("Use the group counter in a with block")
        return self._temporary

    def _write_run(self, records: Iterable[CountedKey]) -> Path:
        path = Path(self._require_open().name) / f"{self._next_id}.run"
        self._next_id += 1
        with path.open("wb", buffering=_IO_BUFFER_BYTES) as stream:
            for key, total, normal, attack in records:
                stream.write(_RUN_HEADER.pack(len(key), total, normal, attack))
                stream.write(key)
        return path

    def _compact(self, paths: list[Path]) -> Path:
        records = _combine_runs(paths)
        try:
            combined = self._write_run(records)
        finally:
            records.close()
        for path in paths:
            path.unlink()
        return combined

    def _flush(self) -> None:
        if not self._chunk:
            return
        path = self._write_run((key, *self._chunk[key]) for key in sorted(self._chunk))
        self._chunk.clear()
        self._chunk_bytes = 0

        # Merge full levels as we go, keeping only a handful of files per level.
        for level in self._levels:
            level.append(path)
            if len(level) < self._merge_fan_in:
                return
            path = self._compact(level)
            level.clear()
        self._levels.append([path])
