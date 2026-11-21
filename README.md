# SentinelAI
AI-Powered Network Intrusion Detection and Incident Management Platform

## G1 dataset inspection

Place your copies of the two prepared UNSW-NB15 partitions in the local,
Git-ignored `data/` directory at the repository root:

- `data/UNSW_NB15_training-set.csv`
- `data/UNSW_NB15_testing-set.csv`

From the repository root in PowerShell, run:

```powershell
& .\.venv\Scripts\python.exe -B ml/inspect_dataset.py
```

This runs the inspector with the virtual environment's Python. The `-B` flag
prevents bytecode cache files. Use `--train` and `--test` to pass different paths,
for example if the files are stored outside the repository.

The training report lists columns and inferred types, row count, blank cells by
column, exact duplicates excluding `id`, binary and attack-category counts, and
unusual service and FTP values. The test check validates CSV syntax, the ordered
header, and row widths and reports the record count. Reserve that partition for
final model evaluation. See [G1 dataset feature analysis](docs/DATASET_ANALYSIS.md)
for the training-only analysis command and findings.

Run the test suite after installing the pinned dependencies in the
[model packaging guide](docs/MODEL_PACKAGING.md):

```powershell
& .\.venv\Scripts\python.exe -B -m unittest discover -s tests -v
```

This discovers tests in `tests/` and lists each result. The tests create their
own temporary CSV fixtures.

## G5 local inference

See the [model packaging guide](docs/MODEL_PACKAGING.md) to train the selected
48-tree Random Forest, create its local package, and score the synthetic CSV.
