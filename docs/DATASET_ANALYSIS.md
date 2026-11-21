# G1 dataset feature analysis

## Scope and reproduction

Run these commands from the repository root in PowerShell with the prepared CSVs
in the Git-ignored `data/` directory and the existing Python 3.12.3 environment.

```powershell
& .\.venv\Scripts\python.exe -B ml/inspect_dataset.py
& .\.venv\Scripts\python.exe -B -m ml.analyze_training
& .\.venv\Scripts\python.exe -B -m unittest discover -s tests -v
```

The inspector profiles the training CSV and checks the official test CSV for
valid CSV syntax, the same ordered header, consistent row widths, and record
count. The second command reads only the training CSV and reports duplicate
groups, conflicting labels, hypothetical class-balance changes, and feature
anomalies. The third runs the fixture-based tests. No dataset records are written
or removed by either script.

The training CSV has 175,341 rows and 45 columns. Inferred types are 30 integer,
11 decimal, and four text columns. Every column has zero empty or whitespace-only
cells. The official test CSV passed the structural checks with 82,332 rows and
the same 45 columns. These row counts match UNSW's published partition sizes.
The official test partition is reserved for final evaluation.
[UNSW-NB15 dataset](https://research.unsw.edu.au/projects/unsw-nb15-dataset)

## Duplicate and conflicting records

- Comparing every field except `id` leaves 107,740 distinct records and
  67,601 excess occurrences (38.55% of training rows).
- Comparing the 42 predictor fields after excluding `id`, `label`, and
  `attack_cat` leaves 101,040 distinct feature vectors and 74,301 excess
  occurrences (42.38%). Both counts use exact CSV field values.
- There are 229 distinct feature vectors with both binary labels. Their groups
  contain 940 rows (0.54%), including 396 normal and 544 attack rows. A classifier
  using only these predictors receives identical inputs for both labels in each
  of these groups. The available columns cannot establish why the labels differ.

| Attack category | Total training rows | Rows in conflicting groups | Share of category |
|---|---:|---:|---:|
| Analysis | 2,000 | 0 | 0.00% |
| Backdoor | 1,746 | 0 | 0.00% |
| DoS | 12,264 | 0 | 0.00% |
| Exploits | 33,393 | 0 | 0.00% |
| Fuzzers | 18,184 | 543 | 2.99% |
| Generic | 40,000 | 0 | 0.00% |
| Normal | 56,000 | 396 | 0.71% |
| Reconnaissance | 10,491 | 0 | 0.00% |
| Shellcode | 1,133 | 1 | 0.09% |
| Worms | 130 | 0 | 0.00% |

Fuzzers accounts for 543 of the 544 affected attack rows. Excluding all
conflicting groups would therefore affect Fuzzers more than other attack
categories.

## Hypothetical class balance

| Counting policy | Rows | Normal | Attack |
|---|---:|---:|---:|
| Original | 175,341 | 56,000 (31.94%) | 119,341 (68.06%) |
| One per exact record excluding `id` | 107,740 | 51,890 (48.16%) | 55,850 (51.84%) |
| One per unambiguous feature vector, with conflicting vectors excluded | 100,811 | 51,661 (51.25%) | 49,150 (48.75%) |

The last row combines feature-level deduplication and conflict exclusion.
Record multiplicity substantially changes the observed class balance. Document
the counting policy when comparing later experimental results.

## Service and FTP fields

- `service = "-"` occurs in 94,168 rows (53.71%), including 36,512 normal
  rows and 57,656 attack rows. It occurs across protocols, including TCP
  (46,208), UDP (15,848), and `unas` (12,084). Keep the literal as its own
  category for the baseline while its precise meaning in the prepared
  partition remains unverified.
- `is_ftp_login` frequencies are 172,774 zeros, 2,545 ones, six twos, and
  sixteen fours. All 22 nonbinary rows have `service = "ftp"`, and each of
  those rows has `ct_ftp_cmd` equal to the nonbinary value. The authors'
  feature table describes `is_ftp_login` as binary. The observed match
  does not establish the cause or provide a rule for recoding those rows.
  Preserve the raw values, encode the field as categorical for the baseline,
  and consider a training-only sensitivity check with the field omitted.
  [Moustafa and Slay, Table VI](https://www.researchgate.net/publication/287330529_UNSW-NB15_a_comprehensive_data_set_for_network_intrusion_detection_systems_UNSW-NB15_network_data_set)

## First baseline preparation

1. Use `label` as the target and exclude `id` and `attack_cat` from predictors.
   Build group IDs from the selected predictor values after deterministic
   parsing and before fitting any transformations. Recompute groups if
   predictor selection or deterministic recoding changes which rows are
   identical.
2. Use reproducible, stratified group cross-validation on the official
   training partition. Keep every identical-vector group in one fold,
   verify zero group overlap, and record fold class counts and the seed.
   Keep conflict rows with their original labels for the primary comparison.
   Treat deduplication or conflict exclusion as an explicitly reported
   training-only sensitivity analysis.
3. Compare a majority-class reference with a simple logistic regression
   pipeline. Fit categorical encoding and numeric scaling within each
   training fold. Report the confusion matrix, precision, recall, F1, and
   false-positive rate. Fix the preprocessing and evaluation choices before
   opening the official test partition for final scoring.
