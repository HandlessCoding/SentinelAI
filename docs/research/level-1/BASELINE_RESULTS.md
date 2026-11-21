# G2 binary intrusion-detection baseline

## Reproduce the experiment

From the repository root in PowerShell, use the existing Python 3.12.3 virtual
environment. Place the prepared training CSV at
`data/UNSW_NB15_training-set.csv`.

```powershell
& .\.venv\Scripts\python.exe -B -m pip install --only-binary=:all: -r ml/requirements-baseline.txt
& .\.venv\Scripts\python.exe -B -m unittest discover -s tests -v
& .\.venv\Scripts\python.exe -B -m ml.run_baseline --smoke
& .\.venv\Scripts\python.exe -B -m ml.run_baseline
```

The first command installs pinned dependencies into the virtual environment.
The second runs the automated suite. The third runs both pipelines on up to
600 evenly spaced training rows to check the full workflow. The final command
runs both models on all training rows and prints a JSON report with fold
counts, metrics, warnings, library versions, and the training file SHA-256.
Both experiment modes use the training CSV as their sole data input.

## Method

- The target is `label`, with normal traffic encoded as 0 and attack traffic as
  1. The 42 predictors exclude `id`, `label`, and `attack_cat`.
- Three shuffled `StratifiedGroupKFold` splits use seed 42. Group IDs identify
  identical tuples of raw CSV predictor values before preprocessing. All rows,
  including duplicate records and conflicting-label groups, contribute to the
  full experiment. Each fold checks for zero shared groups before fitting.
  [StratifiedGroupKFold](https://scikit-learn.org/1.7/modules/generated/sklearn.model_selection.StratifiedGroupKFold.html)
- A fresh `Pipeline` and `ColumnTransformer` fit each model within each
  training fold. `OneHotEncoder(handle_unknown="ignore")` encodes `proto`,
  `service`, `state`, and `is_ftp_login`. The literal `service="-"` and
  raw FTP login codes are retained. `StandardScaler` centers and scales the
  numerical predictors using fold training statistics.
- `DummyClassifier(strategy="most_frequent")` is the majority-class reference.
  `LogisticRegression` uses L2 regularization, `C=1`, the `liblinear` solver,
  at most 1,000 iterations, seed 42, and the default decision rule.
  [LogisticRegression](https://scikit-learn.org/1.7/modules/generated/sklearn.linear_model.LogisticRegression.html)
- Metrics treat attack as positive. Confusion matrix rows are actual classes
  and columns are predicted classes, ordered normal then attack. The
  false-positive rate is FP / (TN + FP). Unweighted fold summaries use
  the population standard deviation (divide by three).

## Results

The smoke run completed all three folds on 600
rows (198 normal and 402 attack) in 586 groups.
Each fold had zero shared groups. The full run used all 175,341 rows,
including 56,000 / 119,341 (68.06%) normal / attack (attack share), across
101,040 distinct raw predictor groups. It used 42 predictors.

Training CSV SHA-256 is
`bec7dd5ec88dc2a0ccc7a07879d338395ed7421750f675fd0339e07dfe0648fa`.

Runtime versions were python 3.12.3, scikit-learn 1.7.2, numpy 2.2.6, scipy 1.15.3, joblib 1.5.2, threadpoolctl 3.6.0.

### Fold composition and group isolation

Class columns show normal / attack counts, with attack share in parentheses.

| Fold | Training classes | Validation classes | Training groups | Validation groups | Shared groups |
|---:|---:|---:|---:|---:|---:|
| 1 | 37,339 / 79,497 (68.04%) | 18,661 / 39,844 (68.10%) | 67,381 | 33,659 | 0 |
| 2 | 37,214 / 80,328 (68.34%) | 18,786 / 39,013 (67.50%) | 67,335 | 33,705 | 0 |
| 3 | 37,447 / 78,857 (67.80%) | 18,553 / 40,484 (68.57%) | 67,364 | 33,676 | 0 |

### Validation metrics by fold

| Fold | Model | Accuracy | Balanced accuracy | Precision | Recall | F1 | False-positive rate | TN | FP | FN | TP |
|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | Dummy | 0.6810 | 0.5000 | 0.6810 | 1.0000 | 0.8103 | 1.0000 | 0 | 18,661 | 0 | 39,844 |
| 1 | Logistic regression | 0.9347 | 0.9045 | 0.9219 | 0.9878 | 0.9537 | 0.1788 | 15,325 | 3,336 | 485 | 39,359 |
| 2 | Dummy | 0.6750 | 0.5000 | 0.6750 | 1.0000 | 0.8060 | 1.0000 | 0 | 18,786 | 0 | 39,013 |
| 2 | Logistic regression | 0.9345 | 0.9054 | 0.9203 | 0.9886 | 0.9533 | 0.1777 | 15,447 | 3,339 | 444 | 38,569 |
| 3 | Dummy | 0.6857 | 0.5000 | 0.6857 | 1.0000 | 0.8136 | 1.0000 | 0 | 18,553 | 0 | 40,484 |
| 3 | Logistic regression | 0.9362 | 0.9058 | 0.9244 | 0.9877 | 0.9550 | 0.1761 | 15,285 | 3,268 | 499 | 39,985 |

### Mean ± standard deviation across folds

| Metric | Dummy | Logistic regression |
|---|---:|---:|
| Accuracy | 0.6806 ± 0.0044 | 0.9351 ± 0.0007 |
| Balanced accuracy | 0.5000 ± 0.0000 | 0.9052 ± 0.0005 |
| Precision | 0.6806 ± 0.0044 | 0.9222 ± 0.0017 |
| Recall | 1.0000 ± 0.0000 | 0.9880 ± 0.0004 |
| F1 | 0.8099 ± 0.0031 | 0.9540 ± 0.0007 |
| False-positive rate | 1.0000 ± 0.0000 | 0.1776 ± 0.0011 |

Confusion matrix counts summarized cell by cell across folds.

| Model | TN | FP | FN | TP |
|---|---:|---:|---:|---:|
| Dummy | 0.00 ± 0.00 | 18666.67 ± 95.21 | 0.00 ± 0.00 | 39780.33 ± 602.22 |
| Logistic regression | 15352.33 ± 68.90 | 3314.33 ± 32.79 | 476.00 ± 23.34 | 39304.33 ± 579.37 |

The dummy model predicted attack for every row. Logistic regression preserved
high attack recall while lowering false alarms substantially. It still labeled
9,943 of 56,000 normal validation rows as attacks across the three folds.

### Verification and execution notes

All 14 automated tests passed, and `pip check` reported consistent dependencies.
Both experiment runs completed without model or convergence warnings. The
initial dependency installation ran out of space while using the C: temporary
directory. The retry completed with pip caching disabled and temporary files
on D: inside the existing virtual environment.

## Limitations and next experiment

The metrics describe three group-aware splits of the prepared training
partition from one seed. Exact raw grouping prevents the same raw predictor
vector from appearing on both sides of a fold. It leaves possible overlap
among near-duplicates, differently formatted equivalent values, or related
flows. Repeated records contribute to row-level scores, and conflicting labels
limit what the observed features can distinguish. Generalization to the
official holdout and to operational network traffic remains unmeasured.

For the next experiment, use inner group-aware validation to select a
decision threshold against a specified false-positive budget, then report
the recall and false-positive rate on the outer validation folds. Use the
default-threshold logistic regression above as the comparison and keep the
official test partition reserved for final evaluation.
