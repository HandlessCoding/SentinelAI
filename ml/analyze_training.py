"""Report duplicate groups and feature anomalies in the training CSV."""

import argparse
from collections import Counter
import csv
from pathlib import Path
import sys

from ml.inspect_dataset import read_header, read_rows


def analyze_training(path):
    """Group rows by their exact CSV feature values and count labels within groups."""
    vectors = {}
    categories = Counter()
    ftp_values = Counter()
    unusual_ftp = Counter()
    service_dash_by_label = Counter()
    service_dash_by_proto = Counter()

    with path.open(encoding="utf-8-sig", newline="") as file:
        reader = csv.reader(file, strict=True)
        columns = read_header(reader)
        required = {"service", "proto", "is_ftp_login", "ct_ftp_cmd"}
        if missing := required.difference(columns):
            raise ValueError(f"CSV header is missing columns: {', '.join(sorted(missing))}")
        feature_indices = [
            index for index, name in enumerate(columns)
            if name not in {"id", "label", "attack_cat"}
        ]
        for row in read_rows(reader, columns):
            fields = dict(zip(columns, row))
            label = fields["label"]
            if label not in {"0", "1"}:
                raise ValueError(f"CSV line {reader.line_num} has an invalid binary label")
            category = fields["attack_cat"]
            key = tuple(row[index] for index in feature_indices)
            if key not in vectors:
                vectors[key] = Counter()
            vectors[key][label, category] += 1
            categories[category] += 1

            ftp = fields["is_ftp_login"]
            service = fields["service"]
            ftp_values[ftp] += 1
            if ftp not in {"0", "1"}:
                unusual_ftp[ftp, service, fields["ct_ftp_cmd"]] += 1
            if service == "-":
                service_dash_by_label[label] += 1
                service_dash_by_proto[fields["proto"]] += 1

    if not vectors:
        raise ValueError("CSV contains no data rows")

    original = Counter()
    exact_dedup = Counter()
    unambiguous_dedup = Counter()
    conflict_categories = Counter()
    conflicting_vectors = 0
    for outcomes in vectors.values():
        group_labels = {label for label, category in outcomes}
        conflicting = len(group_labels) > 1
        if conflicting:
            conflicting_vectors += 1
        else:
            unambiguous_dedup[next(iter(group_labels))] += 1
        for (label, category), count in outcomes.items():
            original[label] += count
            exact_dedup[label] += 1
            if conflicting:
                conflict_categories[category] += count

    return {
        "original": original,
        "exact_dedup": exact_dedup,
        "unambiguous_dedup": unambiguous_dedup,
        "unique_vectors": len(vectors),
        "conflicting_vectors": conflicting_vectors,
        "categories": categories,
        "conflict_categories": conflict_categories,
        "ftp_values": ftp_values,
        "unusual_ftp": unusual_ftp,
        "service_dash_by_label": service_dash_by_label,
        "service_dash_by_proto": service_dash_by_proto,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--train", type=Path, default=Path("data/UNSW_NB15_training-set.csv")
    )
    args = parser.parse_args(argv)
    try:
        report = analyze_training(args.train)
    except (OSError, ValueError, csv.Error) as error:
        print(f"Training CSV ({args.train}): {error}", file=sys.stderr)
        return 1

    total = sum(report["original"].values())
    affected = sum(report["conflict_categories"].values())
    print(f"Training rows: {total:,}")
    print(f"Exact duplicates excluding id: {total - sum(report['exact_dedup'].values()):,}")
    print(f"Distinct feature vectors: {report['unique_vectors']:,}")
    print(f"Duplicate feature rows beyond first occurrence: {total - report['unique_vectors']:,}")
    print(f"Conflicting feature vectors: {report['conflicting_vectors']:,}")
    print(f"Rows in conflicting groups: {affected:,} ({affected / total:.2%})")
    print("Conflict rows by category (affected / category total):")
    for category, count in sorted(report["categories"].items()):
        conflicts = report["conflict_categories"][category]
        print(f"  {category}: {conflicts:,} / {count:,} ({conflicts / count:.2%})")
    for name, description in (
        ("original", "Original training rows"),
        ("exact_dedup", "Hypothetical exact deduplication excluding id"),
        ("unambiguous_dedup", "Hypothetical one row per unambiguous vector, excluding conflicts"),
    ):
        counts = report[name]
        rows = sum(counts.values())
        print(f"{description} ({rows:,} rows):")
        for label, class_name in (("0", "normal"), ("1", "attack")):
            share = f"{counts[label] / rows:.2%}" if rows else "n/a"
            print(f"  {class_name}: {counts[label]:,} ({share})")

    print("is_ftp_login frequencies:", dict(sorted(report["ftp_values"].items())))
    print("Unusual FTP combinations (is_ftp_login, service, ct_ftp_cmd):")
    for values, count in sorted(report["unusual_ftp"].items()):
        print(f"  {values}: {count:,}")
    print("service = '-' counts by label:", dict(sorted(report["service_dash_by_label"].items())))
    print("service = '-' most frequent protocols:", report["service_dash_by_proto"].most_common(10))
    print("Validation: group by exact predictor vector before splitting training data.")
    print("Keep each group in one fold and check the class balance of each fold.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
