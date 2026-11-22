# G16 · Experimental Level 2 baseline

## Decision and scope

The approved NF-ToN-IoT-v2 development release supports a bounded
**exploratory pilot**. A three-fold partition satisfying the prespecified
size and class criteria was infeasible on the 250,000-row graph sample.
The model comparison therefore uses exact-vector isolation. The CSV
lacks the provenance needed to check capture or session independence.
The benchmark reserved in G13, the frozen Level 1 model, and G10's
evaluation stayed outside this experiment.
[G13 strategy](LEVEL_2_DATA_STRATEGY.md) · [G14 audit](LEVEL_2_DATA_AUDIT.md) · [G15 findings](LEVEL_2_FEATURE_ENGINEERING.md)

## Connected-group feasibility

The runner reads the approved CSV after verifying its recorded SHA-256.
It draws fixed-seed samples without replacement from row ordinals
using the G15 reader. It counts distinct exported five-tuples after
normalizing IPv4 address and port values, ordering the two endpoint
pairs, and keeping IP protocol. For protocols without TCP/UDP ports,
the address slots and exported pseudo-port slots form an exporter
proxy. Different time-separated sessions can share any of these keys.
IP addresses and the port slots stay in local grouping data.

Rows sharing an exact typed six-field vector or a tuple are connected.
Each transitive component is indivisible. Grouping on the six-field
core also isolates exact vectors from all tested extensions, since
each retains all six core predictors. The prespecified feasibility
criteria were three validation folds with 20–45% of all sampled rows
and at least 15% of each binary class in each fold.

| Measure | 12,000-row smoke sample | 250,000-row feasibility sample |
| --- | ---: | ---: |
| Benign / attack | 4,259 / 7,741 | 89,871 / 160,129 |
| Distinct exported tuples | 11,963 | 237,054 |
| Distinct core vectors | 2,979 | 31,728 |
| Connected components | 2,947 | 25,113 |
| Components with both classes | 34 | 323 |
| Singleton components | 2,458 | 18,922 |
| Largest component | 2,451 | 115,987 |
| Benign / attack in largest | 2,115 / 336 | 73,307 / 42,680 |

The next four components in the 250,000-row sample contain 33,607,
30,689, 10,082, and 3,337 rows. The largest component already holds
46.39% of all rows and 81.57% of the benign examples. Only 16,564
benign examples remain for the other two folds together, below
the 30% aggregate minimum. This rules out an assignment meeting
the criteria on that sample. The smoke sample's proposed grouped
folds also failed the balance criteria. These are sample-based
feasibility results. The full-release graph size was unmeasured.

## Exploratory experiment

The pilot uses three stratified group folds on identical six-field
vectors. Each outer training fold has a separate exact-group
calibration split. The first fold from a fixed calibration splitter
supplies calibration records, and each classifier fits only the
other records from that outer training fold. All candidates use the
same fit, calibration, and outer validation rows. The default rule
is strictly above 0.5. The packet-length-plus-flags candidate also
explores 5% and 10% false-positive budgets. It chooses thresholds
on calibration scores from the fitted model, maximizing attack
recall among finite thresholds within the budget. For tied recall
the rule prefers lower false-positive rate, then a higher threshold.
An infeasible calibration budget remains infeasible. The selected
rule is applied with `>=` on outer scores, without refitting.
[Grouped validation documentation](https://scikit-learn.org/1.7/modules/generated/sklearn.model_selection.StratifiedGroupKFold.html) · [Threshold documentation](https://scikit-learn.org/1.7/modules/classification_threshold.html)

The six feature configurations are the G14 core, core plus IP
packet-length extrema, core plus TCP masks, core plus both, core
plus TTL extrema, and core plus retransmission counters. Ports,
IP addresses, labels and attack categories never enter the model
matrix. G15 documented the source meanings and showed that exporter
parity remains unresolved. TTL and retransmission comparisons are
nProbe ablations. They do not demonstrate compatibility with stock
Zeek logs. The runner represents structurally inapplicable fields
by -1 and preserves measured zeros. It one-hot encodes protocol
and TCP masks with unknown categories ignored. Logistic Regression
scales numerical inputs from its fit rows. Random Forest uses the
unscaled numerical inputs. All learned preprocessing fits inside
each fold.
[Feature definitions and compatibility](LEVEL_2_FEATURE_ENGINEERING.md#feature-definitions-and-portability)

Logistic Regression uses liblinear and a 500-iteration cap. The
forest uses 24 trees, depth 10, at most 256 leaves per tree, at least
20 samples per leaf, and a 0.67 bootstrap sample fraction. The
seed for sampling, outer splitting and estimators is 42. Calibration
uses seed 43. The forest and numerical libraries run with one worker
or thread. A 12,000-row smoke run took 24.27 seconds including the
file checksum and sampling pass. The larger model pilot was capped
at 120,000 rows. The separate 250,000-row graph audit took 27.60
seconds and fitted no models. The program saves aggregate JSON
only. There is no experimental model package.

## Measured pilot results

The pilot accepted all **120,000 rows** (42,945 benign and 77,055 attack)
and took 84.47 seconds including loading and checksum verification. It
found 16,393 connected components, compared with 18,451 core vector
groups and 116,759 distinct exported tuples. The largest component
contained 50,050 rows, including 34,219 benign and 15,831 attack rows.
The remaining components hold only 8,726 benign records, less than
the combined requirement for the other two folds. The pilot used
the exact-vector-only fallback.

| Fold | Fit benign / attack | Calibration benign / attack | Validation benign / attack | Tuples shared with outer development rows | Validation rows sharing those tuples |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1 | 4,339 / 28,747 | 2,394 / 10,821 | 36,212 / 37,487 | 1,299 | 1,424 |
| 2 | 26,559 / 37,843 | 12,793 / 14,058 | 3,593 / 25,154 | 1,322 | 1,432 |
| 3 | 37,848 / 49,515 | 1,957 / 13,126 | 3,140 / 14,414 | 1,164 | 1,233 |

All fit, calibration, and validation partitions had disjoint exact
vectors within each fold. The shared tuple counts above compare each
validation fold with its combined fit and calibration rows. These
measure residual overlap in exported keys. Session and capture overlap
remain unknown. Fold 1 alone held 36,212 of the 42,945 benign records,
so the other folds represent substantially different class and group
mixtures.

### Default operating point

These are pooled out-of-fold results on the shared pilot sample.
Confusion matrix entries are shown as TN, FP, FN, TP. Attack is the
positive class.

| Features | Model | Accuracy | Balanced accuracy | Precision | Recall | FPR | F1 | ROC AUC | TN, FP, FN, TP |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| Core | Logistic | 59.34% | 47.02% | 62.73% | 90.37% | 96.34% | 74.05% | 0.3275 | 1,573, 41,372, 7,421, 69,634 |
| Core | Forest | 64.91% | 53.28% | 65.86% | 94.20% | 87.63% | 77.52% | 0.4775 | 5,311, 37,634, 4,469, 72,586 |
| Packet lengths | Logistic | 56.84% | 45.34% | 61.81% | 85.78% | 95.09% | 71.85% | 0.4354 | 2,107, 40,838, 10,959, 66,096 |
| Packet lengths | Forest | 64.99% | 53.45% | 65.94% | 94.07% | 87.17% | 77.53% | 0.5719 | 5,508, 37,437, 4,573, 72,482 |
| TCP flags | Logistic | 61.08% | 50.42% | 64.43% | 87.93% | 87.10% | 74.37% | 0.6902 | 5,541, 37,404, 9,302, 67,753 |
| TCP flags | Forest | 65.37% | 53.76% | 66.09% | 94.61% | 87.08% | 77.82% | 0.7029 | 5,548, 37,397, 4,155, 72,900 |
| Lengths and flags | Logistic | 61.26% | 50.82% | 64.65% | 87.54% | 85.91% | 74.37% | 0.6181 | 6,053, 36,892, 9,599, 67,456 |
| Lengths and flags | Forest | 66.00% | 54.79% | 66.64% | 94.21% | 84.63% | 78.06% | 0.6355 | 6,600, 36,345, 4,458, 72,597 |
| TTL | Logistic | 53.23% | 42.46% | 60.17% | 80.32% | 95.40% | 68.80% | 0.2081 | 1,976, 40,969, 15,161, 61,894 |
| TTL | Forest | 65.61% | 54.11% | 66.27% | 94.59% | 86.37% | 77.94% | 0.6425 | 5,852, 37,093, 4,170, 72,885 |
| Retransmissions | Logistic | 59.78% | 47.48% | 62.96% | 90.75% | 95.79% | 74.34% | 0.3667 | 1,806, 41,139, 7,126, 69,929 |
| Retransmissions | Forest | 62.97% | 51.59% | 65.02% | 91.61% | 88.43% | 76.06% | 0.5294 | 4,967, 37,978, 6,463, 70,592 |

Each extension also includes the core. The combined forest had the
lowest measured default FPR among these configurations, still
**84.63%**. TCP flags alone yielded the highest pooled ROC AUC
for both models. Pooled ROC AUC combines scores from different fits.
For the combined forest, the individual fold AUCs were 0.5067, 0.8405,
and 0.9653. Its default fold FPRs were 93.92%, 38.10%, and 30.73%.
The spread and the exceptionally large first fold limit the value of
any single pooled configuration ranking.

### Threshold exploration for lengths and flags

| Model | Calibration budget | Selected thresholds in folds 1–3 | Validation FPRs in folds 1–3 | Folds meeting budget | Pooled FPR | Pooled recall |
| --- | ---: | --- | --- | ---: | ---: | ---: |
| Logistic | 5% | 0.96686 / 0.91118 / 0.95502 | 30.06% / 4.59% / 5.35% | 1 of 3 | 26.13% | 37.31% |
| Logistic | 10% | 0.89272 / 0.91118 / 0.94986 | 31.48% / 4.59% / 5.48% | 2 of 3 | 27.33% | 43.91% |
| Forest | 5% | 0.88129 / 0.77169 / 0.92558 | 29.99% / 6.74% / 2.39% | 1 of 3 | 26.02% | 54.58% |
| Forest | 10% | 0.78139 / 0.77169 / 0.82064 | 30.80% / 6.74% / 6.08% | 2 of 3 | 26.98% | 57.42% |

All calibration folds found finite thresholds within their own budget.
Neither budget held on every validation fold or in pooled predictions.
At the forest's 10% calibration operating point, the pooled confusion
counts were 31,357 TN, 11,588 FP, 32,810 FN and 44,245 TP. Threshold
changes reduced false alarms at a large cost in attack recall. The
pilot did not justify a new operating threshold for use outside it.

### Ambiguous vectors and attack categories

Ambiguity slices are descriptive and defined using both labels across
the sampled release. Because validation leaves complete vectors
outside fitting, this analysis does not feed validation labels into
training. The combined projection has 68,465 rows in conflicting
groups, with 33,951 benign and 34,514 attack records. Group conflict
outside the sample can be missed by this definition.

| Combined-feature model | Group label status | Attack recall | FPR among benign |
| --- | --- | ---: | ---: |
| Logistic | Conflicting | 83.58% | 96.79% |
| Logistic | Single label | 90.76% | 44.81% |
| Forest | Conflicting | 96.25% | 98.56% |
| Forest | Single label | 92.56% | 32.05% |

The forest's high recall on conflicting vectors coincides with
flagging nearly all benign flows in those groups. Core-only forests
also falsely flagged 98.70% of benign rows in conflicting groups.
The combined fields reduced some ambiguity, and considerable false
alarms persisted in the observed single-label groups.

| Published attack category | Support | Combined logistic recall | Combined forest recall |
| --- | ---: | ---: | ---: |
| Backdoor | 105 | 100.00% | 100.00% |
| DDoS | 14,333 | 98.04% | 99.18% |
| DoS | 5,034 | 62.61% | 90.94% |
| Injection | 4,925 | 91.33% | 98.78% |
| MITM | 44 | 61.36% | 65.91% |
| Password | 8,335 | 93.15% | 99.70% |
| Ransomware | 20 | 20.00% | 100.00% |
| Scanning | 27,043 | 93.23% | 86.77% |
| XSS | 17,216 | 73.43% | 98.79% |

These are binary attack detections grouped by the publisher's category,
with no multiclass predictions. The low support for MITM and Ransomware
limits category-specific conclusions. The results describe a testbed
sample with residual dependence and uneven folds. They support no
comparison with the frozen Level 1 official test or claim of
generalization.

## Requirements for stronger validation

Use a manifest tying each row to its original capture or verified time
block, with capture hashes, collection campaign, environment, sensor,
exporter version and settings, and UTC bounds. Session groupings need
documented session identifiers or timestamped tuple reconstruction
with an agreed timeout policy. ToN-IoT v3 may support a separate
within-lineage temporal experiment if approved. It is a separate
extraction, and G15 found no documented row crosswalk to v2.
For credible cross-environment validation, acquire separately sourced
development captures with independent benign and attack coverage.
Check the connected components and class support before selecting a
model. Keep the reserved evaluation campaign sealed until the model
and protocol are frozen. [G15 provenance research](LEVEL_2_FEATURE_ENGINEERING.md#leakage-and-development-split)

## Reproduce

Run from the repository root with the existing pinned Python environment
and the official G14 CSV in its ignored directory.

```powershell
$release = 'data/level2/nf-ton-iot-v2'
& .\.venv\Scripts\python.exe -B -m ml.run_level2_experiment --rows 12000 |
    Set-Content -Encoding utf8 "$release/g16-smoke.json"
& .\.venv\Scripts\python.exe -B -m ml.run_level2_experiment --rows 250000 --audit-only |
    Set-Content -Encoding utf8 "$release/g16-graph.json"
& .\.venv\Scripts\python.exe -B -m ml.run_level2_experiment --rows 120000 |
    Set-Content -Encoding utf8 "$release/g16-pilot.json"
& .\.venv\Scripts\python.exe -B -m unittest discover -s tests
```

The pilot JSON contains validation-fold metrics, aggregate confusion
matrices in TN/FP and FN/TP order, threshold choices, ambiguity slices,
and category support and recall for every model. [Runner](../../../ml/run_level2_experiment.py) · [Synthetic tests](../../../tests/test_level2_experiment.py)

The recorded run used Python 3.12.3, NumPy 2.2.6, and scikit-learn 1.7.2.
All **118 Python tests** and **22 frontend tests** passed, along with the
frontend production build. The frozen Level 1 artifact matched its
recorded digest. The CSV and aggregate run JSON are ignored by Git.

## G32 UNSW-NB15 development restart

### Prior evidence and scope

G1 identified repeated predictors and conflicting labels. G2–G4 kept
exact raw-vector groups together and established a training-only comparison
and threshold baseline. G5 packaged the selected forest. G10 reported
**84.90% accuracy, 99.35% attack recall, and 32.81% false-positive rate** on
the official UNSW-NB15 test partition. Those figures are historical context.
G32 accesses only the official training CSV and uses a newly fitted G4 forest
as its same-partition reference.
[G1 analysis](../level-1/DATASET_ANALYSIS.md) ·
[G3 thresholds](../level-1/THRESHOLD_ANALYSIS.md) ·
[G4 forest](../level-1/MODEL_COMPARISON.md) ·
[G10 evaluation](../../FINAL_MODEL_EVALUATION.md)

Conflicting labels prevent a deterministic classifier from separating some
identical inputs. G10 also measured a 32.735% FPR among test rows without an
exact training match. Exact overlap alone cannot explain the false-alarm
burden. The high-recall operating point, overlapping class scores, and shift
in feature distributions or scenario coverage are plausible contributors.
Attack prevalence affects precision and overall accuracy. It does not by
itself explain a class-conditional FPR change.
[G10 overlap and limitations](../../FINAL_MODEL_EVALUATION.md#exact-predictor-overlap)

G13–G16 identified exporter differences and provenance or grouping limits in
NF-ToN-IoT-v2. G17–G19 found that the corrected CIC-IDS2017 chronology could
not meet the prespecified overlap and retention gates. G20–G24 could not
verify adequate independent IoT-23 positive coverage and benign label
provenance. G32 therefore investigates benchmark behavior within a single
UNSW feature contract. UNSW's engineered fields have no validated mapping to
the current Zeek collector. The reserved 2018 benchmark stays sealed.
[Dataset strategy](LEVEL_2_DATA_STRATEGY.md) ·
[CIC-IDS2017 decision](LEVEL_2_CHRONOLOGICAL_BASELINE.md#decision) ·
[IoT-23 decision](LEVEL_2_IOT23_CAPTURE_RECONCILIATION.md)

### Prespecified split and operating points

- Pin the training CSV by SHA-256. Use all 42 predictors and exclude `id`,
  `label`, and `attack_cat`. Keep `service = "-"` and the original FTP values
  categorical. Parse numerical strings as finite float64 values so equivalent
  spellings share a group.
- Use seven stratified group folds, with seed `32042` assigning group IDs
  before the ordered allocator. Allocate folds 0–3 to fitting, 4 to
  calibration, 5 to model comparison, and 6 to final development validation.
  Require complete row coverage, zero overlap for raw and normalized keys,
  at least 1,000 rows of each class per role, and attack share within 7.5
  percentage points of the full CSV. Keep all conflicting rows. Labels in
  the final role contribute to split construction and coverage checks only
  before model and threshold selection. The CSV lacks capture identifiers
  needed to check session dependence or near-duplicate leakage.
- Fit the G2 Logistic Regression and G4 48-tree Random Forest pipelines on
  the fit role. Add histogram gradient boosting with 100 iterations, fixed
  model seed `42`, fit-only ordinal category encoding and native categorical
  splits. Disable early stopping. Use one worker and one native thread.
  [Grouped splitting](https://scikit-learn.org/1.7/modules/generated/sklearn.model_selection.StratifiedGroupKFold.html) ·
  [Histogram gradient boosting](https://scikit-learn.org/1.7/modules/generated/sklearn.ensemble.HistGradientBoostingClassifier.html)
- On calibration, choose the lowest FPR with at least 95% recall. Break ties
  by higher recall and then higher threshold. The calibrated rule includes
  score ties. The default reference uses scores strictly above 0.5. The
  scores are used for thresholding without probability recalibration.
- Select the lowest-FPR candidate with at least 95% recall on comparison.
  If none meets the floor, record the failure and select by highest recall,
  then lowest FPR, for a diagnostic final check. Inspect feature importance
  using permutation of individual raw columns on 1,024 comparison rows
  with seed `32043` and two repeats. Importance plays no part in selection.
  Write the winner, pipeline digest, and threshold before scoring the final
  partition once.

Run from the repository root with the pinned Python environment and the
official training CSV at `data/UNSW_NB15_training-set.csv`. Use a fresh
ignored directory for a reproduction of this experiment.

```powershell
$env:LOKY_MAX_CPU_COUNT = '1'
& .\.venv\Scripts\python.exe -B -m ml.run_unsw_development --output data/g32-reproduction
```

The ignored output includes a split audit, zero-based CSV data-row indices,
candidate reports, the frozen experimental pipeline, an exclusive final-score
marker, and final metrics. A reproduction uses the same already evaluated
development partition. It provides no new blind evidence.
[Runner](../../../ml/run_unsw_development.py) ·
[Split and audit](../../../ml/unsw_development_split.py)

### Split audit

The pinned CSV SHA-256 is
`bec7dd5ec88dc2a0ccc7a07879d338395ed7421750f675fd0339e07dfe0648fa`.
The split passed every gate and retained all 175,341 rows. Raw and normalized
keys both gave 101,040 distinct vectors and 74,301 repeated rows beyond the
first occurrence. All six role pairs shared zero groups under both key
definitions. The 229 conflicting groups cover 940 rows. The minority labels
within those groups establish a lower bound of 321 errors for a deterministic
classifier of those exact inputs across the full CSV. This bound leaves other
errors unexplained.

| Role | Rows | Normal | Attack | Conflicting groups |
| --- | ---: | ---: | ---: | ---: |
| Fit | 100,199 | 32,002 | 68,197 | 140 |
| Calibration | 25,048 | 8,000 | 17,048 | 34 |
| Comparison | 25,047 | 7,999 | 17,048 | 27 |
| Final development validation | 25,047 | 7,999 | 17,048 | 28 |

### Calibration and candidate comparison

Each candidate met the calibration recall floor. The table shows the
fixed threshold carried into comparison. Confusion counts are ordered
TN / FP / FN / TP throughout this section.

| Candidate | Threshold | Calibration recall | Calibration FPR | Confusion counts |
| --- | ---: | ---: | ---: | --- |
| Logistic Regression | 0.690879 | 95.02% | 11.03% | 7,118 / 882 / 849 / 16,199 |
| Random Forest | 0.657562 | 95.00% | 6.19% | 7,505 / 495 / 852 / 16,196 |
| Histogram gradient boosting | 0.647878 | 95.04% | 5.46% | 7,563 / 437 / 845 / 16,203 |

| Comparison candidate | Operating point | Accuracy | Recall | FPR | Precision | Balanced accuracy | Confusion counts |
| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| Logistic Regression | Default | 93.66% | 98.84% | 17.36% | 92.38% | 90.74% | 6,610 / 1,389 / 198 / 16,850 |
| Logistic Regression | Calibrated | 93.29% | 94.82% | 9.96% | 95.30% | 92.43% | 7,202 / 797 / 883 / 16,165 |
| Random Forest | Default | 94.92% | 98.79% | 13.34% | 94.04% | 92.73% | 6,932 / 1,067 / 206 / 16,842 |
| Random Forest | Calibrated | 94.48% | 94.53% | 5.61% | 97.29% | 94.46% | 7,550 / 449 / 933 / 16,115 |
| Histogram gradient boosting | Default | 95.54% | 97.67% | 8.98% | 95.87% | 94.34% | 7,281 / 718 / 398 / 16,650 |
| Histogram gradient boosting | Calibrated | 94.97% | 94.91% | 4.90% | 97.63% | 95.00% | 7,607 / 392 / 868 / 16,180 |

None of the calibrated candidates retained 95% recall on comparison.
The prespecified fallback selected gradient boosting at its frozen
threshold `0.6478775510084671`. Compared with the newly fitted forest's
calibrated result, it missed 65 fewer attacks and flagged 57 fewer normal
rows on the same comparison partition.

Comparison score distributions overlap in the tails. Gradient boosting's
normal median and 95th percentile were 0.00017 and 0.643, while its attack
median and fifth percentile were 0.99951 and 0.645. Permuting `sttl` gave
its largest mean balanced-accuracy drop, 0.389 on the 1,024-row diagnostic
sample. Logistic Regression was most sensitive to `dttl` and `swin`, and
the forest to `ct_srv_dst`. These rankings depend on the sampled rows,
feature correlations, and the selected operating points. In particular,
strong dependence on source TTL warrants checking whether the signal
transfers beyond this cyber range.

### Frozen final development validation

The selected pipeline SHA-256 is
`62ba7c74d99e37afceb1243ed7ae1234631c19f23e4da06a7a2bfd4e27941fd4`.
One scoring pass produced scores for 7,999 normal and 17,048 attack rows.
The default row applies the prespecified reference rule to those same scores.

| Operating point | Accuracy | Recall | FPR | Precision | Balanced accuracy | Confusion counts |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| Default 0.5 | 95.48% | 97.74% | 9.33% | 95.71% | 94.20% | 7,253 / 746 / 386 / 16,662 |
| Frozen calibrated | 95.11% | 95.32% | 5.35% | 97.43% | 94.99% | 7,571 / 428 / 797 / 16,251 |

The frozen threshold avoided 318 false positives at the cost of 411
additional missed attacks versus its default decision rule. Its F1 was
96.37%. The shared score vector yielded ROC AUC 0.99275 and average
precision 0.99655. The 5% FPR target was missed and the threshold was left
frozen. This result measures development within one prepared dataset.
Independent capture validation and live feature parity remain open.

Fit times were 6.10 seconds for Logistic Regression, 28.84 seconds for the
forest, and 7.48 seconds for gradient boosting. The run took 129.36 seconds
wall time and 128.14 seconds process CPU time, with about 765 MiB peak
resident memory. The frozen experimental pipeline is 433,132 bytes. The
candidate fits emitted no warnings. The recorded run used Python 3.12.3,
scikit-learn 1.7.2, and the existing [pinned dependencies](../../../ml/requirements-baseline.txt).

## G32.1 unattended fitting-only research

The runner verifies the original G32 partition archive by SHA-256 and reads
only its `fit` member. It streams the pinned training CSV as bytes for the
integrity check and copies only the 100,199 selected data lines into ignored
storage. Features and labels are parsed from that fitting-only copy. G32's
calibration, comparison, and final development rows supply no model input.
The UNSW official test CSV and the reserved 2018 benchmark stay sealed.

The full plan crosses nine recipes with three feature sets for **27
configurations**. Recipes include histogram gradient boosting, Random Forest,
and Logistic Regression with bounded complexity, regularization, and class
weights. XGBoost and LightGBM were absent from the existing environment.
The feature sets retain all predictors, remove `sttl`, `dttl`, and
`ct_state_ttl`, or additionally remove the remaining `ct_*` fields and
`is_sm_ips_ports`. The smallest feature set defines exact-vector groups.
Five rotations assign one fold to evaluation, the next to calibration, and
the remaining three to fitting. Each rotation verifies disjoint groups across
all feature sets, at least 500 rows per class and role, and attack share within
10 percentage points of the fitting-only input. All original fitting rows are
retained in the plan.

The detached run's preflight passed. It verified 32,002 normal and 68,197
attack rows and zero group overlap in all five rotations. Evaluation folds
contain 6,400–6,401 normal rows and 13,639–13,640 attack rows. Removing the
context fields enlarged the biggest exact-vector group from 415 to 6,711
rows. The common grouping keeps that complete group on one side of each
boundary. The separate smoke run completed ten folds across two configurations
on 6,000 fitting-only rows with zero failures.

Each threshold minimizes calibration FPR at a recall floor of 95%. Ranking
prefers configurations that hold the recall floor on every evaluation fold,
then lowest mean and worst-fold FPR. If none passes, the report ranks by
highest minimum recall and marks the shortfall. The report pairs ablations
with the corresponding full-feature recipe and gives fold-wise recall and FPR
differences. Full-feature runs also measure permutation importance on 384
evaluation rows per fold. TTL sensitivity and context-feature sensitivity are
diagnostics for possible shortcuts. They cannot establish environmental
transfer. Fold ranges and standard deviations describe stability across the
five rotations, which share fitting rows across rotations.

From the repository root, run the smoke test before starting the hidden
Windows worker. All paths below are ignored local storage.

```powershell
$env:LOKY_MAX_CPU_COUNT = '3'
$env:OMP_NUM_THREADS = '2'
$env:OPENBLAS_NUM_THREADS = '2'
$env:MKL_NUM_THREADS = '2'
$env:BLIS_NUM_THREADS = '2'
& .\.venv\Scripts\python.exe -B -m ml.run_unsw_overnight run --smoke --output data/g32-1-smoke
$python = (Resolve-Path .venv/Scripts/python.exe).Path
Start-Process -FilePath $python -ArgumentList @('-B','-m','ml.run_unsw_overnight','run') `
    -WorkingDirectory (Get-Location).Path -WindowStyle Hidden `
    -RedirectStandardOutput data/g32-1-launch.stdout.log `
    -RedirectStandardError data/g32-1-launch.stderr.log
```

The full run checkpoints under `data/g32-1-overnight/`. The runner uses one
candidate at a time, up to three forest workers, and two native threads.
The watchdog stops at the eight-hour wall deadline or when observed peak
resident memory reaches 8 GiB. Results already published remain available.
`state.json` records the Python worker PID. `report.json` is refreshed after
each terminal configuration. The `report` command assembles the current
report from all durable checkpoints, including incomplete configurations.

```powershell
& .\.venv\Scripts\python.exe -B -m ml.run_unsw_overnight status
& .\.venv\Scripts\python.exe -B -m ml.run_unsw_overnight report
& .\.venv\Scripts\python.exe -B -m ml.run_unsw_overnight stop
```

The stop command requests a checkpoint-boundary stop. A native fit may need
to return before the worker can act. To resume, repeat the run command with
the original code and directory. The runner retains the original deadline
and skips saved folds and terminal configurations. G33 needs a prespecified
validation protocol and new independent, feature-compatible captures before
any exploratory winner can support a generalization claim.
[Runner](../../../ml/run_unsw_overnight.py) ·
[Synthetic tests](../../../tests/test_unsw_overnight.py)

## G32.2 extended overnight study

### What G32.1 showed

G32.1 finished 27 configurations and 135 folds in about 15 minutes. None
held 95% recall on all five evaluation folds. Logistic Regression without TTL
had the highest worst-fold recall (94.90%) and 15.97% mean FPR. The reference
gradient-boosted model achieved 95.02% mean recall and 6.43% mean FPR, with
94.53% worst-fold recall. Its calibration recall was close to the 95% floor
each time. Fold 1 moved from 5.30% calibration FPR to 7.33% evaluation FPR,
and fold 5 fell from 95.00% calibration recall to 94.53% evaluation recall.
That variation motivates a recall buffer and a separate threshold role. The
fold summaries cannot identify a cause for individual errors.

Source TTL dominated the reference boosted model's permutation diagnostic
(0.372 mean balanced-accuracy drop). Removing TTL changed its mean FPR
by only −0.003 percentage points and mean recall by −0.059 points, consistent
with other features carrying similar information. Removing the much broader
context set raised mean FPR by 2.219 points. In Logistic Regression, dropping
TTL raised mean FPR by 4.634 points, and the full recipe was sensitive to
destination TTL and sender window. These findings motivate narrower,
matched ablations and comparisons of capacity, penalties, sampling, and
class weights. They establish neither a causal shortcut nor transferability.

### Staged protocol

- **Discovery** evaluates 184 new estimator and feature configurations across
  five rotations. The budget is 108 boosted trees, 60 forests, and 16
  Logistic Regression variants. Fit and feature parameters differ from G32.1.
  Every recipe has a matched full and TTL-free case. A subset separates
  source TTL from destination TTL or removes selected service context counters.
  XGBoost and LightGBM were unavailable in the existing environment.
- **Data roles** use exactly the verified 100,199 original G32 fit rows.
  Hold out one of six group folds as the G32.2 challenge. Discovery rotates
  the remaining cohort across disjoint model fit, probability fit, threshold
  selection, and evaluation roles. The intersection of the feature contracts
  defines grouping. Each role requires both classes and zero overlap under
  every feature set. The training CSV checksum uses opaque bytes. Only the
  rows named by the original G32 fit indices are materialized and decoded.
- **Decisions** compare raw scores, sigmoid on score log-odds, and isotonic
  probabilities. The probability role alone fits the maps. Within each
  mapping the threshold role minimizes FPR at recall floors of 95%, 96.5%,
  and 99%. Raw scores at 0.5 provide a reference. A configuration reuses the
  same fitted estimator for those analyses. Report Brier score and log loss
  separately from threshold performance. [Probability calibration](https://scikit-learn.org/1.7/modules/calibration.html)
- **Stability** promotes at most 12 discovery candidates across model and
  ablation families. Their selected policies repeat on two new discovery
  seeds. Ranking prefers holding 95% recall on every fold, then lower mean
  and worst-fold FPR. If none holds the floor, highest worst-fold recall
  determines the diagnostic ranking. Model and policy selection ends here.
- **Locked challenge** evaluates the frozen primary choice and up to two
  feature-contract comparators. The estimator, probability map, and thresholds
  are fitted exclusively within discovery. An access marker precedes scoring,
  so an interrupted challenge with uncertain access stays unavailable. The
  challenge is locked within G32.2. G32.1 previously studied the underlying fit
  rows, and seed repeats reuse discovery observations. Neither stage provides
  independent environment validation.

The report records confusion matrices and denominators by fold, policy and
seed, as well as mean, worst-fold and range summaries. Paired ablations use
the same raw 96.5% calibration policy. Error slices show false positives and
misses by protocol, service, and source TTL range. Finalists also record a
fitting-sample versus evaluation AUC diagnostic. These distributions can guide
G33 protocol design. Their fold spread does not provide independent sampling
uncertainty. G33 needs new compatible, independently reviewed captures with a
model and decision policy fixed in advance.

### Run and monitor

Use the existing Python environment. This smoke test uses synthetic inputs
and exercises discovery, seed replication, and the locked scoring path.

```powershell
$env:LOKY_MAX_CPU_COUNT = '3'
$env:OMP_NUM_THREADS = '2'
$env:OPENBLAS_NUM_THREADS = '2'
$env:MKL_NUM_THREADS = '2'
$env:BLIS_NUM_THREADS = '2'
& .\.venv\Scripts\python.exe -B -m ml.run_unsw_extended run --smoke --output data/g32-2-smoke
$python = (Resolve-Path .venv/Scripts/python.exe).Path
Start-Process -FilePath $python -ArgumentList @('-B','-m','ml.run_unsw_extended','run') `
    -WorkingDirectory (Get-Location).Path -WindowStyle Hidden `
    -RedirectStandardOutput data/g32-2-launch.stdout.log `
    -RedirectStandardError data/g32-2-launch.stderr.log
```

The detached worker uses `data/g32-2-extended/`. It completes one model at a
time with up to three forest workers and two native threads. The watchdog
applies the original eight-hour deadline and an observed 8 GiB peak-memory
limit. Each finished fold is saved atomically. Resume with the original run
command, code, and directory. Resume skips saved folds and keeps the deadline.
The report command reads current checkpoints and the final run saves
`report.json`. A stop request takes effect at a safe checkpoint.

```powershell
& .\.venv\Scripts\python.exe -B -m ml.run_unsw_extended status
& .\.venv\Scripts\python.exe -B -m ml.run_unsw_extended report
& .\.venv\Scripts\python.exe -B -m ml.run_unsw_extended stop
```

[Extended runner](../../../ml/run_unsw_extended.py) ·
[Synthetic regression tests](../../../tests/test_unsw_extended.py)

## G33 error analysis and qualification

G32 is the four-way, training-only development study. G32.1 and G32.2
reuse only its 100,199 original fitting rows. G32.1 completed 27
configurations across 135 folds. G32.2 completed 184 discovery
configurations, 24 seed-replication jobs, and two challenge jobs across
1,042 folds, with zero failed or missing jobs. It took about 4 hours and
48 minutes and peaked at 597 MiB of resident memory. The audit reconciled
both reports with their checkpoints, verified the fitting snapshot and
split audits, recomputed discovery-only selection, and checked the two
challenge markers and decision policies. Neither the original G32 final
validation partition, the official UNSW test partition, nor the reserved
2018 benchmark was opened for G33. [Checkpoint verifier](../../../ml/verify_unsw_research.py)

### Frozen internal challenge

The challenge used 5,333 normal and 11,364 attack rows. Counts and scores
below are from G32.2. No new challenge predictions or threshold decisions
were made. These observations share the UNSW capture and feature-export
lineage used for fitting. The challenge was locked within G32.2, and G32.1
had already studied the underlying G32 fitting pool.

| Candidate | Isotonic threshold | TN / FP / FN / TP | Recall | FPR | Precision | Accuracy | Balanced accuracy |
| --- | ---: | --- | ---: | ---: | ---: | ---: | ---: |
| HGB-34 Full | 0.712124 | 5,009 / 324 / 504 / 10,860 | 95.56% | 6.08% | 97.10% | 95.04% | 94.74% |
| HGB-35 No TTL | 0.669014 | 5,017 / 316 / 514 / 10,850 | 95.48% | 5.93% | 97.17% | 95.03% | 94.78% |

Both met the 95% recall floor and missed the 5% FPR target. At this normal
support, a 5% FPR allows at most 266 false positives. HGB-34 exceeded that
count by 58 and HGB-35 by 50. The threshold role realized 95.29% recall and
7.33% FPR for HGB-34 and 95.13% recall and 6.90% FPR for HGB-35. Those
thresholds were selected to minimize FPR while satisfying the 95% recall
floor on that role. A recall-constrained threshold cannot guarantee a
separate FPR target. Precision here reflects an attack share of 68.06%.

| Challenge slice | Normal / attack support | HGB-34 FP / FN | HGB-35 FP / FN |
| --- | ---: | ---: | ---: |
| TCP | 3,705 / 3,881 | 232 / 410 | 220 / 422 |
| UDP | 1,329 / 4,783 | 92 / 94 | 96 / 92 |
| Service `-` | 3,516 / 6,179 | 265 / 431 | 261 / 437 |
| HTTP | 501 / 1,257 | 49 / 54 | 43 / 56 |
| DNS | 715 / 3,098 | 1 / 0 | 2 / 0 |
| Source TTL 128–254 | 1,085 / 9,865 | 292 / 455 | 287 / 467 |
| Source TTL below 32 | 4,035 / 20 | 0 / 0 | 1 / 0 |

These slices overlap. TCP accounted for the most misses for both
candidates, and the high source-TTL band accounted for about 90% of false
positives in each. That band's FPR was 26.91% and 26.45%, respectively.
Lower TTL ranges had different class and traffic mixes. Several protocol
buckets contained traffic from only one class. This concentration remains
after TTL removal and warrants checking correlated features and capture
conditions. The aggregate checkpoints cannot identify which individual
rows changed decisions or provide challenge-level attack-category recalls.

### Stability and TTL sensitivity

Each candidate was scored across 15 discovery evaluations using three
seeds. The table uses the frozen operating policy for each candidate.
Ranges are observed fold extrema. The repeated partitions share the same
rows, so the ranges do not quantify uncertainty across independent captures.

| Discovery candidate | Mean recall (min–max) | Mean FPR (min–max) | Mean precision | Mean accuracy |
| --- | ---: | ---: | ---: | ---: |
| HGB-34 Full | 95.65% (95.003–96.66%) | 7.12% (5.72–8.59%) | 96.63% | 94.77% |
| HGB-28 Full | 95.71% (95.003–97.10%) | 7.18% (5.87–9.41%) | 96.60% | 94.79% |
| HGB-35 No TTL | 95.60% (95.011–96.53%) | 7.19% (5.82–8.68%) | 96.60% | 94.71% |
| HGB-34 No Source TTL | 95.73% (95.12–96.51%) | 7.20% (6.10–8.33%) | 96.59% | 94.79% |
| RF-14 No Source TTL | 95.63% (94.93–96.55%) | 7.51% (6.32–9.23%) | 96.45% | 94.63% |
| LR-05 Full | 95.98% (94.91–97.14%) | 12.95% (11.18–15.47%) | 94.05% | 93.13% |

Across seeds 32242, 32267, and 32291, HGB-34's mean recall/FPR pairs were
95.38%/6.81%, 95.84%/7.37%, and 95.75%/7.17%. HGB-35's were
95.35%/6.89%, 95.59%/7.26%, and 95.86%/7.41%. Neither hit 5% FPR
on any discovery fold. Challenge raw AUC was 0.99237 (fitting sample
0.99794) and 0.99244 (fitting sample 0.99888), respectively. Ranking
separation remains strong, while the in-sample gap and fold spread
counsel caution about estimating future error rates.

HGB-34 Full has 42 predictors, 300 iterations, 0.035 learning rate, L2 of
4.0, and balanced class weights. HGB-35 excludes `sttl`, `dttl`, and
`ct_state_ttl` and uses 235 iterations, 0.055 learning rate, L2 of 1.5,
and normal/attack weights of 1.35/1.0. Both use up to 63 leaves and a
12-row minimum leaf. This recipe comparison cannot isolate a TTL effect.
With the same recipe and raw 96.5% recall calibration policy, eliminating
the three TTL fields raised mean FPR for 39 of 48 HGB recipes (median
change +0.124 percentage points) and 25 of 26 forests (median +0.163
points). All eight Logistic Regression recipes had higher mean FPR
(median +3.890 points). HGB's median recall change was −0.054 points.
TTL and surrounding context retain signal within this dataset. Source
TTL, window sizes, state, and history counters can also encode exporter
and lab conditions. This study cannot establish how much of their signal
will survive another environment.

### Discovery error replay and calibration

The audit replayed only seed 32242 for the frozen recipes, using their
original fitting and probability roles and exact saved fold thresholds.
All ten confusion matrices and fold Brier scores matched the checkpoints.
The reporting code covers 83,502 discovery rows (26,669 normal and
56,833 attack), with one out-of-fold prediction per row per candidate.
It joins `attack_cat` only for analysis and writes only aggregate statistics
under ignored `data/`. The challenge figures above come from saved aggregates.
[Replay and reporting utility](../../../ml/audit_unsw_qualification.py)

| Discovery replay | HGB-34 Full | HGB-35 No TTL |
| --- | ---: | ---: |
| TN / FP / FN / TP | 24,854 / 1,815 / 2,626 / 54,207 | 24,831 / 1,838 / 2,641 / 54,192 |
| Raw → isotonic Brier score | 0.036274 → 0.034445 | 0.034809 → 0.034692 |
| Raw → isotonic ECE (10 equal-width bins) | 0.01850 → 0.00353 | 0.00619 → 0.00256 |
| Median FP calibrated score (5th–95th percentile) | 0.750 (0.627–0.972) | 0.773 (0.640–0.967) |
| Median FN calibrated score (5th–95th percentile) | 0.480 (0.213–0.590) | 0.465 (0.234–0.602) |
| Singleton vectors and their FP / FN | 43,391, with 1,365 / 2,171 | 43,389, with 1,380 / 2,153 |
| Repeated same-label vectors and their FP / FN | 4,541, with 316 / 387 | 4,542, with 329 / 411 |
| Conflicting vectors and their FP / FN | 112, with 134 / 68 | 112, with 129 / 77 |

Conflict groups contain 503 rows in both feature sets. A deterministic
classifier on either contract must make at least 172 errors on those rows.
Most errors occur on singleton vectors. Exact conflicts alone explain only
a small share, even before accounting for near-duplicates or common
capture lineage. Isotonic mapping improved the pooled discovery
probability metrics for both models. The bins above 0.9 contain about
59% of all discovery rows. HGB-34's 0.1–0.2 bin has an average score of
0.167 and observed attack share of 0.242 on 198 rows. Errors include
high-confidence false positives. The challenge checkpoints record Brier
scores of 0.031921 and 0.031959 and log losses of 0.102024 and 0.101532.
Calibration on independent data with a different attack prevalence
remains unverified.

The median FP duration was 0.698 s for HGB-34 and 0.708 s for HGB-35, versus
0.035 s for true normals in both. FN duration medians were 0.609 s and
0.624 s, versus 9 microseconds for true positives in both. False positives
had a median source TTL of 254 and true normals a median of 31 for both.
For HGB-34, destination bytes in false positives had a 5th–95th percentile
range of 0–1,302 and median of 354, versus 0–63,516 and median 1,644 in
true normals. The ranges overlap. Traffic mix and flow semantics may
explain part of these associations, so these summaries do not identify
single-feature causes.

| Discovery attack category | Support | HGB-34 misses | HGB-35 misses |
| --- | ---: | ---: | ---: |
| Fuzzers | 8,803 | 2,282 | 2,273 |
| Analysis | 973 | 120 | 124 |
| Exploits | 16,148 | 174 | 194 |
| DoS | 6,053 | 25 | 25 |
| Shellcode | 532 | 9 | 10 |
| Reconnaissance | 4,236 | 7 | 7 |
| Generic | 19,161 | 5 | 3 |
| Backdoor | 859 | 4 | 5 |
| Worms | 68 | 0 | 0 |

Both models missed Fuzzers, Analysis, and Exploits in all five discovery
folds at this seed. Fuzzers recall was 74.08% and 74.18%. Analysis recall
was 87.67% and 87.26%. This concentration helps explain why strong overall
recall can hide important gaps. Worms support is too small to infer
reliable transfer from zero misses.

To reproduce the audit locally from the repository root, keep the original
G32.1/G32.2 checkpoints and fitting snapshots in their existing ignored
directories. Use a fresh output filename on repeat runs.

```powershell
$env:LOKY_MAX_CPU_COUNT = '3'
$env:OMP_NUM_THREADS = '2'
$env:OPENBLAS_NUM_THREADS = '2'
& .\.venv\Scripts\python.exe -B -m ml.audit_unsw_qualification --output data/g33/verified.json
& .\.venv\Scripts\python.exe -B -m ml.audit_unsw_qualification --replay-discovery --output data/g33/discovery.json
```

### UNSW-to-Zeek feature compatibility

The prepared UNSW models use a 42-predictor contract. The publisher used
Argus, Bro, and additional feature-generation algorithms. SentinelAI's
offline flow store preserves Zeek observation fields, including optional
counters. No full-model or No TTL input can currently be reconstructed
from those fields with verified equivalence.
[UNSW-NB15 publisher](https://research.unsw.edu.au/projects/unsw-nb15-dataset) ·
[Zeek 8.0.11 connection fields](https://docs.zeek.org/en/v8.0.11/scripts/base/protocols/conn/main.zeek.html#type-Conn::Info) ·
[SentinelAI Zeek parser](../../../ml/lab_zeek.py)

| UNSW predictors | Zeek input and reproducibility |
| --- | --- |
| `dur` | `duration_ns` can be converted to seconds when present. Validate flow boundaries, timeout behavior, and UNSW duration semantics before using it. |
| `proto` | Protocol is observed. Verify a shared token set, including ICMP handling. UNSW tokens such as `arp` and `unas` cannot be assumed to map to the same Zeek vocabulary. |
| `spkts`, `dpkts` | `orig_pkts` and `resp_pkts` are available where observed. Validate direction, partial flows, and packet accounting. |
| `sbytes`, `dbytes` | Zeek records directional IP bytes and payload-oriented bytes separately. Exporter reference values are needed to establish equivalent counting. |
| `service`, `state` | Zeek application detection and `conn_state` use exporter-specific semantics. No validated vocabulary crosswalk exists. Missing service differs from a literal UNSW `-` token. |
| `rate`, `sload`, `dload`, `smean`, `dmean` | Need validated input counters, exact formulas and units, and handling of zero or missing duration. Similar names do not specify those choices. |
| `sttl`, `dttl` | Absent from the current connection logs. Would require validated packet-level sampling and direction. |
| `sloss`, `dloss`, `sinpkt`, `dinpkt`, `sjit`, `djit` | Need the exporter's directional packet timing, loss and jitter semantics. Zeek `missed_bytes` is a byte observation, so it cannot supply directional packet losses. |
| `swin`, `dwin`, `stcpb`, `dtcpb`, `tcprtt`, `synack`, `ackdat` | Require exporter-matched TCP windows, sequence bases, and handshake timing. These fields are absent from the ingested connection schema. |
| `trans_depth`, `response_body_len`, `is_ftp_login`, `ct_ftp_cmd`, `ct_flw_http_mthd` | Would require application transaction logs, verified aggregation and join keys, and reproduction of the original categorical FTP encodings. |
| `ct_srv_src`, `ct_state_ttl`, `ct_dst_ltm`, `ct_src_dport_ltm`, `ct_dst_sport_ltm`, `ct_dst_src_ltm`, `ct_src_ltm`, `ct_srv_dst` | Need the original history, order, grouping, and boundaries. A snapshot of connection rows does not recover that context. Any future derivation must be causal and must respect capture boundaries. |
| `is_sm_ips_ports` | Could be derived from endpoint metadata only after validating same-address and same-port semantics, missing operands, tunneling, and direction. |

Protocol, duration, and packet counts are the first candidates for a
reference parity check. Service, state, bytes, and history features
remain unverified. Removing three TTL predictors still leaves 39
features and the principal gaps. The experimental HGB pipeline fits
ordinal encodings for protocol, service, state, and FTP login, and feeds
finite numeric predictors through unchanged. It supports an internal
missing code for unknown categories through its encoder. The proposed
offline input validator should reject and count unrecognized or missing
inputs until that behavior is explicitly qualified for the target export.
Feature values such as the original `-` service and FTP tokens must remain
verbatim. [Experimental preprocessing](../../../ml/unsw_overnight_models.py)

### Offline qualification, latency, and rollback

On the local Windows machine, timing the warm preprocessing, fitted
HGB, and isotonic map of the first replay fold gave the following
milliseconds per batch. The test used two native threads and measured
resident pipeline calls. File parsing, artifact load, input validation,
database, and HTTP time are outside these results.

| Candidate | One row, median / p95 (40 calls) | 100 rows, median / p95 (25 calls) |
| --- | ---: | ---: |
| HGB-34 Full | 12.90 / 14.67 ms | 16.53 / 17.80 ms |
| HGB-35 No TTL | 14.09 / 16.31 ms | 17.86 / 21.29 ms |

1. Use an opt-in offline CLI only after its input exporter is verified.
   It reads bounded batches of compatible records and checks ordered
   columns, types, finite values, categorical vocabulary, and exporter
   version. Invalid inputs fail closed with reportable counts. Keep row
   identifiers and evidence metadata outside predictors, and store
   score outputs separately from alerts, rule findings, and ground truth.
2. A future local package should bind preprocessing, fitted weights,
   calibrator, and inclusive threshold to an immutable version. Its
   manifest should capture ordered feature semantics, dependency versions,
   training row and split digests, seeds, artifact checksums, and the
   approved operating policy. Verify the manifest and artifact against an
   approved local digest before loading. The process must accept only trusted
   locally produced packages, since pickle loading can execute code.
   G33 creates aggregate evidence and no new package.
3. Qualification starts with HGB-34 Full and its frozen isotonic policy
   (`attack_score >= 0.7121240935619471`) and uses HGB-35 No TTL at
   `attack_score >= 0.6690140845070423` as the prespecified comparator.
   These thresholds belong to the exact challenge-fit pipelines and
   calibrators. Deterministic reconstruction would have to verify the
   original non-challenge fit/probability identities and reference scores,
   with no threshold refit. Any refit on different data requires a new
   candidate ID and independently scoped qualification.
4. Keep the experimental path disabled in application configuration.
   A future approved shadow run should record import coverage, rejection
   reasons, latency, and drift with reviewed outcome checks. Disable it
   on manifest, feature parity, or coverage failure. A future switch
   must be reversible by disabling the experimental worker and restoring
   the known package pointer. Level 1 continues serving the frozen Random
   Forest with threshold 0.5, and alert/incident APIs remain unchanged.

### G34 recommendation

Existing G26 evidence has one reviewed benign flow, and G27/G29 have
19 reviewed benign flows across five sessions. They share the same
physical host and lab device pair, use Zeek-native flow semantics, and
include zero independently reviewed real attacks. They can check parser
behavior and coverage for observed fields. They cannot qualify an UNSW
model or support cross-environment detection estimates. G28 stays
deferred. G29 live attack collection remains **blocked**.
[Lab and evidence protocol](../../LAB_GUIDE.md#matched-control-and-label-validation)

The smallest useful G34 experiment is an offline **exporter parity test**.
Process one existing authorized benign PCAP through Zeek and a trusted
reference exporter with documented UNSW field semantics. Freeze that
packet input, versions, direction alignment, exact categorical and counter
criteria, timing tolerance, and missing-field rules before comparison.
Check protocol, duration, packet counts and both byte definitions first,
then report what fraction of either model contract can be verified.
If the reference exporter or full contract cannot be reproduced, take the
separate Zeek-native research path and qualify that feature contract using
independently labeled offline flows. Do not run either HGB on guessed
conversions.

For subsequent dataset-generalization validation, lock the model package
and policy before scoring two or more independently recorded,
feature-compatible campaigns with reviewed normal and attack coverage.
Use original capture/device/environment identities and exact-vector
overlap checks to assess independence. Predeclare category support and
report per-capture counts and uncertainty, including when the support is
too small to verify the 95% recall and 5% FPR targets. Report precision
with attack prevalence. The parity test establishes feature behavior on
its workload only. Live-network evaluation would separately require
authorized passive collection, representative traffic, and independent
review of misses and false alarms. No model is ready for Zeek integration
at G33.
