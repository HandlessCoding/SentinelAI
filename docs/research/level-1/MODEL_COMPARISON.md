# G4 Random Forest comparison

## Reproduction

Run these commands from the repository root in PowerShell with the G2
dependencies installed in the existing Python 3.12.3 virtual environment.
No new dependencies are needed.

```powershell
& .\.venv\Scripts\python.exe -B -m unittest discover -s tests -v
& .\.venv\Scripts\python.exe -B -m ml.run_model_comparison --smoke
& .\.venv\Scripts\python.exe -B -m ml.run_model_comparison
```

The commands run the full test suite, check the pipeline on 600 evenly spaced
training rows, and run the full comparison. The runner prints progress and a
JSON report with the fold audit, metrics, resource measurements, warnings,
library versions, and data SHA-256. Both experiment modes read only
`data/UNSW_NB15_training-set.csv`. The
[G2 baseline](BASELINE_RESULTS.md) and [G3 threshold analysis](THRESHOLD_ANALYSIS.md)
provide the original logistic-regression references.

## Method

- Both models use the same three `StratifiedGroupKFold` outer splits as G2 and
  G3, with shuffle seed 42. A group represents identical tuples of the 42 raw
  predictors. Every row and original label contributes, including the 229
  conflicting-label groups. The loader excludes `id`, `label`, and
  `attack_cat` from the predictors.
- The G2 pipeline one-hot encodes `proto`, `service`, `state`, and
  `is_ftp_login`. The literal `service = "-"` and raw FTP codes remain
  categories. Both models reuse the G2 numeric scaler for consistency. Each
  fit learns encodings and scaling from its own training rows.
- Logistic regression uses the G2 `liblinear` estimator with seed 42 and up to
  1,000 iterations. The forest was fixed at 48 trees, depth at most 14, at most
  512 leaves per tree, a minimum leaf size of 5, and bootstrap samples of 75%
  of the training rows. It draws from the square root of the transformed
  feature count at each split, uses seed 42 and one worker, and runs under the
  same single-thread native-pool limit as logistic regression.
  [RandomForestClassifier documentation](https://scikit-learn.org/1.7/modules/generated/sklearn.ensemble.RandomForestClassifier.html)
- At the default operating point, both models predict attack for a score
  strictly above 0.5. Reported pooled metrics use one outer validation
  prediction per row. Pooled ROC AUC and average precision rank scores from
  the three separate fits together.
- The exploratory forest threshold stage runs if the fixed forest improves
  both pooled balanced accuracy and pooled ROC AUC at the initial comparison.
  Threshold values come from three inner group-aware folds (seed 43) within
  each outer training subset. The selector reuses G3's recall maximization
  under the 5% and 10% false-positive budgets with equal-score handling.
  Once selected, the thresholds are applied to the saved, untouched scores
  for the corresponding outer validation fold.
- Wall-clock fit and batch probability-prediction times include
  preprocessing. They exclude data loading, row slicing, metric calculations,
  and serialization. Pipeline size is the byte length of the fitted pipeline
  serialized to an uncompressed in-memory pickle. It includes preprocessing.
  No fitted models are written to disk.

## Run verification

The smoke run used 600 rows
in 586 groups. All three smoke splits had
zero group overlap. The full run used **175,341 rows**
(56,000 normal and 119,341 attack)
in **101,040 predictor groups**. The training CSV's
SHA-256 matched G2 and G3
(`bec7dd5ec88dc2a0ccc7a07879d338395ed7421750f675fd0339e07dfe0648fa`).
The logistic-regression confusion matrices matched G2 and G3 exactly.

| Fold | Training normal / attack | Validation normal / attack | Training / validation groups | Shared outer groups | Shared inner groups by split |
|---:|---:|---:|---:|---:|---:|
| 1 | 37,339 / 79,497 | 18,661 / 39,844 | 67,381 / 33,659 | 0 | 0 / 0 / 0 |
| 2 | 37,214 / 80,328 | 18,786 / 39,013 | 67,335 / 33,705 | 0 | 0 / 0 / 0 |
| 3 | 37,447 / 78,857 | 18,553 / 40,484 | 67,364 / 33,676 | 0 | 0 / 0 / 0 |

Runtime versions were Python 3.12.3, scikit-learn
1.7.2, NumPy 2.2.6, SciPy 1.15.3,
joblib 1.5.2, and threadpoolctl 3.6.0.
All 26 automated tests passed. Both experiment modes completed without fit or
prediction warnings.

## Default-threshold comparison

Metrics use attack as positive. Average precision (AP) and ROC AUC use
attack scores. Confusion counts are TN, FP, FN, and TP.

| Fold | Model | Accuracy | Balanced accuracy | Precision | Recall | F1 | FPR | ROC AUC | AP | TN | FP | FN | TP |
|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | Logistic regression | 93.469% | 90.453% | 92.186% | 98.783% | 95.371% | 17.877% | 0.9841 | 0.9915 | 15,325 | 3,336 | 485 | 39,359 |
| 1 | Random Forest | 94.826% | 92.617% | 93.988% | 98.717% | 96.295% | 13.483% | 0.9912 | 0.9958 | 16,145 | 2,516 | 511 | 39,333 |
| 2 | Logistic regression | 93.455% | 90.544% | 92.033% | 98.862% | 95.325% | 17.774% | 0.9839 | 0.9914 | 15,447 | 3,339 | 444 | 38,569 |
| 2 | Random Forest | 94.585% | 92.281% | 93.487% | 98.864% | 96.101% | 14.303% | 0.9911 | 0.9956 | 16,099 | 2,687 | 443 | 38,570 |
| 3 | Logistic regression | 93.619% | 90.577% | 92.444% | 98.767% | 95.501% | 17.614% | 0.9841 | 0.9918 | 15,285 | 3,268 | 499 | 39,985 |
| 3 | Random Forest | 94.749% | 92.273% | 93.751% | 98.938% | 96.274% | 14.391% | 0.9912 | 0.9959 | 15,883 | 2,670 | 430 | 40,054 |
| Pooled | Logistic regression | 93.515% | 90.524% | 92.223% | 98.803% | 95.400% | 17.755% | 0.9840 | 0.9916 | 46,057 | 9,943 | 1,428 | 117,913 |
| Pooled | Random Forest | 94.721% | 92.391% | 93.743% | 98.840% | 96.224% | 14.059% | 0.9912 | 0.9958 | 48,127 | 7,873 | 1,384 | 117,957 |

Random Forest detected **44 more attack records** and produced **2,070 fewer
false positives** at the default threshold. Pooled balanced accuracy increased
by **1.87 percentage points**.
Pooled ROC AUC also improved, which triggered the inner threshold stage.

### Measured costs

Aggregate times sum the three outer-fold measurements. Aggregate sizes are
rounded means of the per-fold serialized pipeline sizes.

| Fold | Model | Fit time (s) | Batch prediction time (s) | Pipeline (bytes) |
|---:|---|---:|---:|---:|
| 1 | Logistic regression | 12.174 | 1.159 | 6,039 |
| 1 | Random Forest | 46.500 | 1.927 | 3,120,560 |
| 2 | Logistic regression | 10.542 | 0.941 | 6,025 |
| 2 | Random Forest | 40.046 | 1.651 | 2,876,651 |
| 3 | Logistic regression | 9.618 | 0.916 | 6,040 |
| 3 | Random Forest | 40.357 | 1.587 | 2,936,836 |
| Aggregate | Logistic regression | 32.334 | 3.016 | 6,035 |
| Aggregate | Random Forest | 126.902 | 5.165 | 2,978,016 |

On this machine, the forest took **3.92×**
as long to fit and **1.71×**
as long to score the outer batches. Its mean fitted pipeline was
**2.84 MiB**, versus
**5.89 KiB** for logistic regression.
These local batch measurements depend on hardware and workload, and serialized
size does not measure memory use during training.

## Forest threshold analysis

Both budgets produced finite thresholds in every inner evaluation. Thresholds
are shown to eight decimal places and were applied at full precision.

| Fold | Budget | Selected threshold | Inner recall | Inner FPR | Outer FPR | Outer budget met |
|---:|---:|---:|---:|---:|---:|:---:|
| 1 | 5% | 0.70238428 | 93.558% | 4.997% | 4.710% | Yes |
| 1 | 10% | 0.56592579 | 97.142% | 9.984% | 9.335% | Yes |
| 2 | 5% | 0.69343604 | 93.615% | 4.998% | 5.025% | No |
| 2 | 10% | 0.56753884 | 97.162% | 9.996% | 10.199% | No |
| 3 | 5% | 0.69801619 | 93.571% | 4.999% | 5.115% | No |
| 3 | 10% | 0.56404072 | 97.104% | 9.990% | 10.607% | No |

| Fold | Budget | Accuracy | Balanced accuracy | Precision | Recall | F1 | FPR | TN | FP | FN | TP |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 5% | 94.031% | 94.366% | 97.694% | 93.442% | 95.520% | 4.710% | 17,782 | 879 | 2,613 | 37,231 |
| 1 | 10% | 94.906% | 93.779% | 95.683% | 96.893% | 96.284% | 9.335% | 16,919 | 1,742 | 1,238 | 38,606 |
| 2 | 5% | 94.147% | 94.362% | 97.484% | 93.748% | 95.580% | 5.025% | 17,842 | 944 | 2,439 | 36,574 |
| 2 | 10% | 94.868% | 93.555% | 95.195% | 97.309% | 96.240% | 10.199% | 16,870 | 1,916 | 1,050 | 37,963 |
| 3 | 5% | 94.107% | 94.318% | 97.561% | 93.751% | 95.618% | 5.115% | 17,604 | 949 | 2,530 | 37,954 |
| 3 | 10% | 94.939% | 93.437% | 95.250% | 97.480% | 96.352% | 10.607% | 16,585 | 1,968 | 1,020 | 39,464 |
| Pooled | 5% | 94.095% | 94.348% | 97.580% | 93.647% | 95.573% | 4.950% | 53,228 | 2,772 | 7,582 | 111,759 |
| Pooled | 10% | 94.905% | 93.591% | 95.376% | 97.228% | 96.293% | 10.046% | 50,374 | 5,626 | 3,308 | 116,033 |

### Recall at comparable observed false-positive rates

The logistic values come from the independently tuned G3 thresholds evaluated
on the same three outer folds. These comparisons show attained false-positive
rates because the inner target can differ from the held-out rate.

| Inner budget | Model | Pooled outer FPR | Pooled outer recall | Outer folds within budget | Pooled budget met |
|---:|---|---:|---:|---:|:---:|
| 5% | Logistic regression | 5.021% | 89.455% | 1 of 3 | No |
| 5% | Random Forest | 4.950% | 93.647% | 1 of 3 | Yes |
| 10% | Logistic regression | 9.932% | 94.586% | 2 of 3 | Yes |
| 10% | Random Forest | 10.046% | 97.228% | 1 of 3 | No |

At the 5% operating points, the forest recovered **5,003 more attacks** while
producing **40 fewer false positives** than logistic regression. The forest's
pooled recall advantage was **4.19 percentage points**,
and its pooled FPR was slightly lower. Both models exceeded the 5% budget on
two outer folds.

At the 10% operating points, the forest detected **3,153 more attacks** and
produced **64 more false positives**. Its recall advantage of
**2.64 percentage points**
came with an FPR higher by
**0.11 percentage points**.
The forest exceeded the 10% pooled maximum by 26 false positives. Logistic
regression met the pooled budget and met it on two individual folds.

## Provisional Level 1 recommendation

Use the fixed Random Forest as the provisional Level 1 model and keep
logistic regression as the simpler reference. The forest improved
balanced accuracy and reduced false positives at 0.5 while preserving
attack recall. At about 5% observed FPR it detected materially more attacks
than the tuned logistic policy. Its pipeline remains small for batch scoring,
with a measured cost of longer fits, slower scoring, and a less transparent
decision process than logistic regression's single coefficient vector.

Keep 0.5 as the reproducible reference operating point for the forest. The
5% policy is a candidate for reducing alert volume, with a recall cost versus
the forest's default and budget overruns on individual folds. The subset of
flows represented here, repeat-row weighting, exact raw grouping, and the
single configuration and split seed limit generalization. The official test
partition remains reserved for final evaluation.
