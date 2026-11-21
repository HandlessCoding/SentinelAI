# G10 final UNSW-NB15 evaluation

## Frozen configuration

G10 evaluates the 48-tree `unsw-nb15-rf-v1` pipeline packaged in G5.
The model, its ordered 42-feature schema, and its default decision
threshold of **0.5** were verified before reading the test CSV for
scoring. The existing inference module applies the saved preprocessing
and predicts attack when the attack probability is strictly greater
than 0.5. The evaluator has a fixed artifact, training fingerprint,
feature schema, and threshold.

| Verified file or contract | SHA-256 |
|---|---|
| `pipeline.pkl` | `8c37b095dba6cd0f58931ff91e713b0a05f84678b4829c387c788e196b8e1cd6` |
| Official training CSV used in G4 and G5 | `bec7dd5ec88dc2a0ccc7a07879d338395ed7421750f675fd0339e07dfe0648fa` |
| Ordered feature schema | `474c13dcaf34dff990839d6ccd7e5bc88702d88df551cdc5d2c3005c2f30417d` |

The pre-G10 audit covered tracked source, Git history and the documented
runs. G1 checked the test CSV's header, record widths, CSV syntax, and row
count. G2–G4 loaded the official training partition for fitting,
validation, threshold experiments, and model selection. G5 fitted the
selected pipeline on that training partition, as confirmed by the file
fingerprint in the artifact manifest. G6–G9 used saved-model inference
with synthetic fixtures for verification. The reviewed history shows
no test-partition use for training, tuning, or selection. This finding
covers the recorded project work.
[G1 dataset analysis](DATASET_ANALYSIS.md) · [G4 model comparison](MODEL_COMPARISON.md) · [G5 model packaging](MODEL_PACKAGING.md)

## Reproduce the evaluation

Run from the repository root in PowerShell with the existing Python
3.12.3 environment, the G5 artifact under `artifacts/unsw-nb15-rf-v1/`,
and the two prepared partitions under the Git-ignored `data/` directory.

```powershell
& .\.venv\Scripts\python.exe -B -m ml.evaluate_final
```

The command checks the artifact and training fingerprint before scoring
the complete official test CSV. It uses the existing `ml.inference`
loader and prediction method, processes records in bounded batches, and
prints an aggregate JSON report. The two partitions are read-only.
The binary `label` supplies ground truth. `attack_cat` is used only to
group evaluation results, and `id` is excluded along with both labels
from the 42 predictors.

The confusion matrix uses normal then attack for both true rows and
predicted columns. False-positive rate divides false attacks by all
actually normal records. ROC AUC and average precision use the same
attack scores as the classifier before applying the threshold. Average
precision summarizes precision weighted by increments in recall.
[Scikit-learn average precision](https://scikit-learn.org/1.7/modules/generated/sklearn.metrics.average_precision_score.html)

## Official test results

The evaluator scored all **82,332 records** in
`UNSW_NB15_testing-set.csv`, including 37,000
normal records and 45,332 attacks.
The local test CSV SHA-256 is
`734fe6642edf758f7c94d7d9149426b49d202fe8e7bf0bef47392489c3c0a559`. Both partition fingerprints stayed
the same during the run. The runtime was Python 3.12.3,
scikit-learn 1.7.2, NumPy 2.2.6,
SciPy 1.15.3, joblib 1.5.2, and
threadpoolctl 3.6.0.

For comparison, the [G4 training-only results](MODEL_COMPARISON.md#default-threshold-comparison)
pool three group-aware outer validation folds at the same 0.5 threshold.
Identical raw predictors stayed together within the G4 split design. The
G4 scores came from fold-specific fits on subsets of the training file.
G10 scores come from the single frozen fit on the complete training file.

| Metric | G4 pooled training validation | G10 official test | Change |
|---|---:|---:|---:|
| Accuracy | 94.721% | 84.895% | −9.825 pp |
| Balanced accuracy | 92.391% | 83.268% | −9.123 pp |
| Precision | 93.743% | 78.767% | −14.976 pp |
| Attack recall | 98.840% | 99.347% | +0.507 pp |
| F1 | 96.224% | 87.868% | −8.356 pp |
| False-positive rate | 14.059% | 32.811% | +18.752 pp |
| ROC AUC | 0.9912 | 0.9824 | −0.0087 |
| Average precision | 0.9958 | 0.9869 | −0.0089 |

| Evaluation | Actual class | Predicted normal | Predicted attack |
|---|---|---:|---:|
| G4 pooled validation | Normal | 48,127 | 7,873 |
| G4 pooled validation | Attack | 1,384 | 117,957 |
| G10 official test | Normal | 24,860 | 12,140 |
| G10 official test | Attack | 296 | 45,036 |

Attack recall rose by 0.51 percentage
points, while the false-positive rate rose by
18.75
percentage points. The fixed threshold flagged **12,140 of
37,000 normal records**, roughly
328 false alarms per 1,000 normal rows
in this benchmark. That explains the main drop in balanced accuracy,
which weights attack recall and normal specificity equally. The official
test set also has a smaller attack share (55.060%)
than G4 validation (68.062%).
Precision depends on this mix as well as on the classifier's error rates.

## Attack-category analysis

Recall is binary attack detection within each true attack category.
These estimates use the category labels to interpret errors. The classifier
outputs a binary decision.

| True attack category | Records | Detected | Missed | Attack recall |
|---|---:|---:|---:|---:|
| Analysis | 677 | 677 | 0 | 100.000% |
| Backdoor | 583 | 583 | 0 | 100.000% |
| DoS | 4,089 | 4,089 | 0 | 100.000% |
| Exploits | 11,132 | 11,124 | 8 | 99.928% |
| Fuzzers | 6,062 | 5,777 | 285 | 95.299% |
| Generic | 18,871 | 18,871 | 0 | 100.000% |
| Reconnaissance | 3,496 | 3,494 | 2 | 99.943% |
| Shellcode | 378 | 377 | 1 | 99.735% |
| Worms | 44 | 44 | 0 | 100.000% |
| All attacks | 45,332 | 45,036 | 296 | 99.347% |

Fuzzers accounted for **285 of
296 missed attacks**. Several categories had zero observed misses.
Worms had only 44 rows, so its
observed recall provides limited evidence about other Worms traffic.

## Exact predictor overlap

The audit compared the 42 raw parsed CSV field strings in the frozen
feature order. It ignored `id`, `label`, and `attack_cat`. This matches
G4's grouping definition, including its treatment of alternative numeric
spellings as different strings. It detected **1,302
distinct shared vectors** among 101,040 distinct
training vectors and 53,946 distinct test vectors.
Those shared vectors occur in 10,279 training rows
(5.862%) and **8,541
test rows (10.374%)**. The official metrics
above include every test record.

| Test subset | Records | Normal | Attack | Accuracy | Balanced accuracy | Recall | FPR | ROC AUC |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Seen predictor vector | 8,541 | 1,472 | 7,069 | 93.888% | 82.592% | 99.830% | 34.647% | 0.9989 |
| Unseen predictor vector | 73,791 | 35,528 | 38,263 | 83.854% | 83.262% | 99.258% | 32.735% | 0.9798 |

The shared-vector subset was more attack-heavy and had higher accuracy.
Its normal-traffic false-positive rate was also higher. These comparisons
are descriptive because the subsets differ in class and potentially
category mix. The overlap limits how much of the benchmark tests
previously unseen inputs. The raw-field check leaves near-duplicates,
equivalent numeric spellings, and relationships between flows unmeasured.

## Limits and interpretation

UNSW-NB15 was generated in a cyber range with a mix of normal traffic and
synthetic attacks. Its features were prepared using Argus, Bro-IDS, and
custom algorithms. This evaluation measures the frozen pipeline on one
published split of those prepared feature records. It provides no
direct measurement of live network detection or compatibility with an
operational feature pipeline. [UNSW-NB15 dataset](https://research.unsw.edu.au/projects/unsw-nb15-dataset)

The high attack recall and ROC AUC coexist with a substantial false-alarm
rate at 0.5. On a network with fewer attacks relative to ordinary traffic,
the number of normal records available to generate false alerts is larger
relative to the number of attacks. Operational alert volume and precision
therefore need independent measurement. The 0.5 operating point and the
G5 artifact were kept frozen throughout evaluation.

## Verification

The full suite passed 63 Python tests and 14 frontend tests. The six
new evaluation tests use synthetic CSV fixtures to check the metrics,
category counts, overlap accounting, bounded scoring, and freeze checks.
The post-evaluation artifact digest matched the pre-evaluation digest.
