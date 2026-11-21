"""Inspect prepared UNSW-NB15 CSV partitions without fitting a model."""

import argparse
from collections import Counter
import csv
from pathlib import Path
import re
import sys


INTEGER = re.compile(r"[+-]?[0-9]+")
DECIMAL = re.compile(r"[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?")


def read_header(reader):
    """Read the ordered column names and check the required dataset fields."""
    columns = next(reader, [])
    if not columns or any(not name.strip() for name in columns):
        raise ValueError("CSV header is missing or contains an empty column name")
    if len(set(columns)) != len(columns):
        raise ValueError("CSV header contains duplicate column names")
    required = {"id", "attack_cat", "label"}
    missing = required.difference(columns)
    if missing:
        raise ValueError(f"CSV header is missing required columns: {', '.join(sorted(missing))}")
    return columns


def read_rows(reader, columns):
    """Yield rows after checking that each has the same width as the header."""
    for row in reader:
        if len(row) != len(columns):
            raise ValueError(
                f"CSV line {reader.line_num} has {len(row)} fields, expected {len(columns)}"
            )
        yield row


def inspect_training(path):
    """Count missing cells, duplicate records and binary labels in training data."""
    with path.open(encoding="utf-8-sig", newline="") as file:
        reader = csv.reader(file, strict=True)
        columns = read_header(reader)
        id_index = columns.index("id")
        label_index = columns.index("label")
        missing = dict.fromkeys(columns, 0)
        labels = Counter({0: 0, 1: 0})
        categories = Counter()
        column_types = {name: set() for name in columns}
        unusual = Counter()
        category_index = columns.index("attack_cat")
        service_index = columns.index("service") if "service" in columns else None
        ftp_index = columns.index("is_ftp_login") if "is_ftp_login" in columns else None
        seen_records = set()
        rows = duplicates = 0

        for row in read_rows(reader, columns):
            rows += 1
            for name, value in zip(columns, row):
                value = value.strip()
                if not value:
                    missing[name] += 1
                elif INTEGER.fullmatch(value):
                    column_types[name].add("integer")
                elif DECIMAL.fullmatch(value):
                    column_types[name].add("decimal")
                else:
                    column_types[name].add("text")

            categories[row[category_index]] += 1
            if service_index is not None and row[service_index] == "-":
                unusual["service = '-'"] += 1
            if ftp_index is not None and row[ftp_index].strip() not in {"0", "1", ""}:
                unusual[f"is_ftp_login = {row[ftp_index]!r}"] += 1

            # Ignore the record ID so it cannot hide otherwise identical rows.
            record = tuple(row[:id_index] + row[id_index + 1:])
            if record in seen_records:
                duplicates += 1
            seen_records.add(record)

            label = row[label_index].strip()
            if label not in {"0", "1"}:
                raise ValueError(f"CSV line {reader.line_num} has an invalid binary label")
            labels[int(label)] += 1

        if not rows:
            raise ValueError("CSV contains no data rows")

    return columns, rows, missing, duplicates, labels, column_types, categories, unusual


def validate_testing(path, expected_columns):
    """Check the test header, row widths, and presence of data rows."""
    with path.open(encoding="utf-8-sig", newline="") as file:
        reader = csv.reader(file, strict=True)
        columns = read_header(reader)
        if columns != expected_columns:
            raise ValueError("CSV columns do not match the training header in name and order")
        rows = sum(1 for _ in read_rows(reader, columns))
        if not rows:
            raise ValueError("CSV contains no data rows")
        return rows


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--train", type=Path, default=Path("data/UNSW_NB15_training-set.csv")
    )
    parser.add_argument(
        "--test", type=Path, default=Path("data/UNSW_NB15_testing-set.csv")
    )
    args = parser.parse_args(argv)

    try:
        columns, rows, missing, duplicates, labels, column_types, categories, unusual = (
            inspect_training(args.train)
        )
    except (OSError, ValueError, csv.Error) as error:
        print(f"Training CSV ({args.train}): {error}", file=sys.stderr)
        return 1

    print(f"Training columns ({len(columns)}): {', '.join(columns)}")
    print(f"Training rows: {rows:,}")
    print("Inferred training column types:")
    for name, types in column_types.items():
        if types == {"integer", "decimal"}:
            types = {"decimal"}
        print(f"  {name}: {' + '.join(sorted(types)) or 'unknown'}")
    print("Missing values by column (empty or whitespace-only):")
    for name, count in missing.items():
        print(f"  {name}: {count:,}")
    print(f"Duplicate rows beyond the first occurrence (excluding id): {duplicates:,}")
    print("Training class distribution:")
    for label, name in ((0, "normal"), (1, "attack")):
        count = labels[label]
        print(f"  {label} ({name}): {count:,} ({count / rows:.2%})")
    print("Training attack categories:")
    for category, count in sorted(categories.items()):
        print(f"  {category!r}: {count:,}")
    print("Training sentinel and nonbinary flag values:")
    for value, count in sorted(unusual.items()):
        print(f"  {value}: {count:,}")
    if not unusual:
        print("  None found")

    try:
        test_rows = validate_testing(args.test, columns)
    except (OSError, ValueError, csv.Error) as error:
        print(f"Test CSV ({args.test}): {error}", file=sys.stderr)
        return 1

    print(f"Test CSV structure: valid ({test_rows:,} records)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
