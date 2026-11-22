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
