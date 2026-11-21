"""Measure exact feature ambiguity in the approved NF-ToN-IoT-v2 development file."""

import argparse
from collections import Counter
from contextlib import ExitStack
import csv
from dataclasses import asdict
from functools import lru_cache
from hashlib import file_digest
from io import TextIOWrapper
from itertools import islice
import json
from operator import itemgetter
from os import fstat
from random import Random
from struct import Struct
import sys
from time import perf_counter

from ml.audit_level2_data import INPUT, PUBLISHED_LABELS, file_identity, read_columns
from ml.level2_audit_storage import ExactGroupCounter
from ml.level2_feature_sets import FEATURE_SETS, FeatureSelector
from ml.level2_flow_schema import FlowValidationError
from ml.level2_splits import fold_for_vector


RELEASE_ROWS = sum(PUBLISHED_LABELS.values())
RELEASE_SHA256 = "7751fb955ca50a2c113ec455eddd39ca23fcfa99eb1ab488c4526c43c2a20081"
SEED = 42
CORE_KEY = Struct(">B5Q")
FOLD_COUNT = 3
MAX_SAMPLE_ROWS = 500_000
RUN_RECORD_OVERHEAD = 28


def sampled_rows(source, population, size, seed):
    """Read fixed-seed row ordinals from the release's one-record-per-line CSV."""
    if not 1 <= size <= min(population, MAX_SAMPLE_ROWS):
        raise ValueError("Invalid sample size")
    cursor = 0
    for ordinal in sorted(Random(seed).sample(range(population), size)):
        line = next(islice(source, ordinal - cursor, None), None)
        if line is None:
            raise ValueError("Release ended before a sampled row")
        yield next(csv.reader((line,), strict=True))
        cursor = ordinal + 1
    remainder = population - cursor
    if remainder and next(islice(source, remainder - 1, None), None) is None:
        raise ValueError("Release has fewer physical rows than expected")
    if next(source, None) is not None:
        raise ValueError("Release has more physical rows than expected")


class GroupDiagnostics:
    """Record the largest group and the minimum disagreements imposed by a projection."""

    def __init__(self, *, core=False):
        self.core = core
        self.minority_rows = 0
        self.zero_duration_conflict_rows = self.single_packet_conflict_rows = 0
        self.largest = (b"", 0, 0, 0)

    def observe(self, group):
        key, rows, benign, attack = group
        self.minority_rows += min(benign, attack)
        if rows > self.largest[1] or (rows == self.largest[1] and key < self.largest[0]):
            self.largest = group
        if self.core and benign and attack:
            _, duration, forward, reverse, _, _ = CORE_KEY.unpack(key)
            if duration == 0:
                self.zero_duration_conflict_rows += rows
            if forward + reverse == 1:
                self.single_packet_conflict_rows += rows

    def report(self):
        key, rows, benign, attack = self.largest
        report = {
            "minority_rows": self.minority_rows,
            "largest": {"rows": rows, "benign": benign, "attack": attack},
        }
        if self.core:
            report.update(
                largest_core_values=list(CORE_KEY.unpack(key)) if key else None,
                zero_duration_conflict_rows=self.zero_duration_conflict_rows,
                single_packet_conflict_rows=self.single_packet_conflict_rows,
            )
        return report


class ProxyOverlap:
    """Measure bounded sample overlap of endpoint pairs and transport five-tuples."""

    def __init__(self, columns):
        self.metadata = itemgetter(*(columns.index(name) for name in (
            "IPV4_SRC_ADDR", "IPV4_DST_ADDR", "L4_SRC_PORT", "L4_DST_PORT", "PROTOCOL",
        )))
        self.endpoint_pairs = {}
        self.transport_tuples = {}
        self.fold_classes = [Counter() for _ in range(FOLD_COUNT)]

    @staticmethod
    def observe_group(groups, key, fold_bit):
        mask, count = groups.get(key, (0, 0))
        groups[key] = (mask | fold_bit, count + 1)

    def observe(self, key, row, label):
        fold = fold_for_vector(key, FOLD_COUNT, SEED)
        self.fold_classes[fold][str(label)] += 1
        src, dst, src_port, dst_port, protocol = self.metadata(row)
        fold_bit = 1 << fold
        self.observe_group(self.endpoint_pairs, tuple(sorted((src, dst))), fold_bit)
        if protocol in ("6", "17"):
            endpoints = tuple(sorted(((src, src_port), (dst, dst_port))))
            self.observe_group(self.transport_tuples, (protocol, endpoints), fold_bit)

    @staticmethod
    def summarize(groups):
        total = shared = shared_rows = 0
        for mask, rows in groups.values():
            total += rows
            if mask.bit_count() > 1:
                shared += 1
                shared_rows += rows
        return {
            "groups": len(groups), "rows": total,
            "shared_groups": shared, "rows_in_shared_groups": shared_rows,
        }

    def report(self):
        return {
            "fold_count": FOLD_COUNT, "seed": SEED,
            "fold_classes": [dict(counts) for counts in self.fold_classes],
            "exact_vector_overlap": 0, "capture_overlap": None, "session_overlap": None,
            "endpoint_pairs": self.summarize(self.endpoint_pairs),
            "transport_five_tuples": self.summarize(self.transport_tuples),
        }


def compare_rows(rows, columns, names, scratch, *, chunk_bytes, diagnostic=None, progress=None):
    """Use the same eligible rows for all exact comparisons in one run."""
    selector = FeatureSelector(names)
    get_values = selector.bind(columns).get_values
    label_index = columns.index("Label")
    proxy = ProxyOverlap(columns) if diagnostic else None
    if diagnostic and diagnostic not in names:
        raise ValueError("Diagnostic feature set must be in the comparison")
    labels, joint_labels = Counter(), Counter()
    protocols = Counter()
    missing = Counter()
    rejections = {name: Counter() for name in names}
    with ExitStack() as stack:
        counters = {
            name: stack.enter_context(ExactGroupCounter(scratch, max_chunk_bytes=chunk_bytes))
            for name in names
        }

        def pack_selection(values):
            blanks = tuple(
                name for name, value in zip(selector.source_columns, values, strict=True)
                if not value.strip()
            )
            packed = []
            protocol = None
            for spec, feature_values in zip(selector.sets, selector.prepare_values(values).values(), strict=True):
                if isinstance(feature_values, FlowValidationError):
                    packed.append((None, f"{feature_values.column}.{feature_values.reason}"))
                    continue
                protocol = feature_values[0]
                packed.append((spec.pack(feature_values), None))
            return blanks, tuple(packed), protocol

        repeated = lru_cache(maxsize=16_384)(pack_selection)
        for number, row in enumerate(rows, 1):
            if len(row) != len(columns) or row[label_index] not in ("0", "1"):
                raise ValueError(f"Invalid width or binary label at compared record {number:,}")
            label = int(row[label_index])
            labels[label] += 1
            values = get_values(row)
            prepare = repeated if sum(map(len, values)) <= 256 else pack_selection
            blank_columns, packed, protocol = prepare(values)
            if blank_columns:
                missing.update(blank_columns)
            eligible = True
            for name, (key, detail) in zip(names, packed, strict=True):
                if key is None:
                    rejections[name][detail] += 1
                    eligible = False
            if eligible:
                joint_labels[label] += 1
                protocols[protocol] += 1
                for name, (key, _) in zip(names, packed, strict=True):
                    counters[name].add(key, label)
                    if proxy is not None and name == diagnostic:
                        proxy.observe(key, row, label)
            if progress is not None and number % 250_000 == 0:
                progress(f"Compared {number:,} records")
        if not labels:
            raise ValueError("No records to compare")
        comparisons = {}
        for name, counter in counters.items():
            if progress is not None:
                progress(f"Merging exact groups for {name}")
            evidence = GroupDiagnostics(core=name == "core")
            comparisons[name] = asdict(counter.finish(on_group=evidence.observe))
            spec = FEATURE_SETS[name]
            structural_nulls = {
                feature.name: sum(
                    count for protocol, count in protocols.items()
                    if protocol not in feature.protocols
                )
                for feature in spec.features if feature.protocols is not None
            }
            comparisons[name].update(
                canonical_columns=spec.columns, key_bytes=spec.key_bytes,
                rejections=dict(rejections[name]),
                structural_nulls={column: count for column, count in structural_nulls.items() if count},
                **evidence.report(),
            )
    return {
        "records": sum(labels.values()), "classes": dict(labels),
        "joint_rows": sum(joint_labels.values()), "joint_classes": dict(joint_labels),
        "raw_missing": {name: missing[name] for name in selector.source_columns},
        "comparisons": comparisons, "proxy_overlap": proxy.report() if proxy else None,
    }


def run_release(names, *, prefix=None, sample=None, chunk_bytes, diagnostic=None, progress=None):
    with INPUT.open("rb") as source:
        original = fstat(source.fileno())
        sha256 = file_digest(source, "sha256").hexdigest()
        if sha256 != RELEASE_SHA256:
            raise ValueError("Input does not match the approved NF-ToN-IoT-v2 release digest")
        source.seek(0)
        with TextIOWrapper(source, encoding="utf-8-sig", newline="") as decoded:
            reader = csv.reader(decoded, strict=True)
            columns = read_columns(reader)
            selection = reader
            if sample is not None:
                selection = sampled_rows(decoded, RELEASE_ROWS, sample, SEED)
            elif prefix is not None:
                selection = islice(reader, prefix)
            start = perf_counter()
            report = compare_rows(
                selection, columns, names, INPUT.parent,
                chunk_bytes=chunk_bytes, diagnostic=diagnostic, progress=progress,
            )
            scanned = fstat(source.fileno())
    if file_identity(original) != file_identity(scanned) or file_identity(original) != file_identity(INPUT.stat()):
        raise ValueError("Source CSV changed during comparison")
    expected = sample or prefix or RELEASE_ROWS
    if report["records"] != expected:
        raise ValueError(f"Expected {expected:,} compared rows")
    report.update(
        sha256=sha256, mode="sample" if sample else "prefix" if prefix else "full",
        sample_seed=SEED if sample else None, seconds=round(perf_counter() - start, 3),
        estimated_chunk_bytes_per_set=chunk_bytes,
        unmerged_run_bytes_upper=sum(
            RELEASE_ROWS * (FEATURE_SETS[name].key_bytes + RUN_RECORD_OVERHEAD) for name in names
        ),
    )
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--sample", type=int, metavar="ROWS")
    mode.add_argument("--prefix", type=int, metavar="ROWS")
    mode.add_argument("--full", action="store_true")
    parser.add_argument("--set", action="append", choices=FEATURE_SETS, dest="names")
    parser.add_argument("--diagnose-folds", choices=FEATURE_SETS)
    parser.add_argument("--chunk-mib", choices=(8, 16, 32), type=int, default=16)
    args = parser.parse_args(argv)
    count = args.sample if args.sample is not None else args.prefix
    if count is not None and not 1 <= count <= MAX_SAMPLE_ROWS:
        parser.error(f"Bounded comparison needs 1 to {MAX_SAMPLE_ROWS:,} rows")
    if args.diagnose_folds and count is None:
        parser.error("Endpoint overlap diagnostics require a bounded comparison")
    def progress(message):
        print(message, file=sys.stderr, flush=True)

    try:
        report = run_release(
            tuple(args.names or FEATURE_SETS), prefix=args.prefix, sample=args.sample,
            chunk_bytes=args.chunk_mib * 1024 * 1024,
            diagnostic=args.diagnose_folds, progress=progress,
        )
    except (OSError, ValueError, csv.Error) as error:
        print(f"Feature comparison failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
