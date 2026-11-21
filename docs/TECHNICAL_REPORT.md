# SentinelAI Level 1 Technical Report

- **Project** — AI-Powered Network Intrusion Detection and Incident Management Platform
- **Course** — SWE497 Software Engineering Graduation Project
- **Scope** — Level 1 implementation and recorded G1–G11 results

## Abstract

SentinelAI is a local decision-support application for evaluating prepared network-flow records and investigating suspected attacks. It combines a scikit-learn classifier with a FastAPI service, PostgreSQL persistence, and a React dashboard. Three group-aware validation folds on the official UNSW-NB15 training partition were used to compare a majority-class reference, logistic regression, and a 48-tree Random Forest. The selected forest was then fitted to the full training partition, frozen, and evaluated on the official test partition at its fixed 0.5 threshold. It detected 45,036 of 45,332 attacks (**99.35% recall**) and flagged 12,140 of 37,000 normal records (**32.81% false-positive rate**). The software supports an end-to-end investigation workflow on prepared input. The benchmark result also shows a substantial analyst review burden and leaves live-network effectiveness unmeasured. [Model comparison](research/level-1/MODEL_COMPARISON.md) · [Final evaluation](FINAL_MODEL_EVALUATION.md) · [Reliability testing](RELIABILITY_TESTING.md)

## 1. Problem and objectives

Network-flow features summarize observed connections and traffic patterns. A supervised model can score those features for similarities to labeled attacks, but its predictions still require interpretation. Missed attacks and false alarms have different consequences. Even a classifier with high attack recall can overwhelm an analyst if it frequently flags benign traffic. A useful evaluation must therefore show how many attacks the model catches and how often it escalates ordinary records.

Level 1 had three objectives:

1. Establish a reproducible binary classifier for the two prepared UNSW-NB15 partitions and quantify its detection and false-alarm performance.
2. Provide a local workflow for validating prepared records, reviewing prediction scores, saving suspected alerts, opening investigations, and recording notes.
3. Verify software behavior under malformed inputs, repeated submissions, concurrent writes, and service failures. Document the limits of the evaluation and the conditions needed to reproduce the system.

The input is a prepared feature table. The application has no live capture, operational feature extraction, authentication, or automatic blocking. Investigations are opened by the analyst. [Dashboard setup and workflows](DASHBOARD_SETUP.md)

## 2. Research background

Moustafa and Slay introduced UNSW-NB15 in 2015 to address gaps in older intrusion-detection benchmarks. The traffic was generated in a cyber range and combines normal activity with synthesized attacks across nine attack types. UNSW provides prepared partitions with documented sizes. These allow a repeatable tabular experiment with a designated evaluation split, while the capture environment and feature extraction limit how directly it represents another network. [Moustafa and Slay (2015), *UNSW-NB15: A Comprehensive Data Set for Network Intrusion Detection Systems*, MilCIS, pp. 1–6](https://digital.library.adelaide.edu.au/items/d4e54baf-85d4-4e46-9028-e8ca66c9f46b) · [UNSW dataset documentation](https://research.unsw.edu.au/projects/unsw-nb15-dataset)

The dataset maintainers also point to a statistical study of UNSW-NB15 and KDD99, two statistical anomaly-detection approaches, and a study that re-expresses intrusion-detection datasets using NetFlow features. The NetFlow study is particularly relevant to future work because evaluating a common flow schema requires deciding which measurements can be reproduced across datasets. [Moustafa and Slay (2016), UNSW-NB15 and KDD99 statistical comparison](https://doi.org/10.1080/19393555.2015.1125974) · [Moustafa, Slay, and Creech (2019), geometric area analysis](https://doi.org/10.1109/TBDATA.2017.2715166) · [Moustafa, Creech, and Slay (2017), finite Dirichlet mixture models](https://doi.org/10.1007/978-3-319-59439-2_5) · [Sarhan et al. (2021), NetFlow datasets for intrusion detection](https://doi.org/10.1007/978-3-030-72802-1_9)

Breiman’s Random Forest combines randomized decision trees, including random feature selection at splits. Tree splits allow interactions among features, which motivated comparing the forest with the linear logistic regression baseline on the same splits. The experiment tests one bounded forest configuration and measures the additional compute and storage cost. [Breiman (2001), *Random Forests*, Machine Learning 45, pp. 5–32](https://www.stat.berkeley.edu/~breiman/randomforest2001.pdf)

Saito and Rehmsmeier demonstrated the importance of inspecting precision and recall when class frequencies are imbalanced. SentinelAI reports both ROC AUC and average precision for score ranking, plus confusion counts and class-specific rates at the fixed operating point. Sommer and Paxson discuss the gap between controlled intrusion-detection evaluations and operational settings, including costly errors, variable network data, and the interpretation of detections. Those concerns motivate the project’s separate assessment of false alarms and the analyst review workflow. [Saito and Rehmsmeier (2015), *PLOS ONE* 10(3), e0118432](https://doi.org/10.1371/journal.pone.0118432) · [Sommer and Paxson (2010), *Outside the Closed World*, IEEE Symposium on Security and Privacy, pp. 305–316](https://www.icir.org/robin/papers/oakland10-ml.pdf)

## 3. Dataset and preprocessing

The prepared training file has **175,341 rows and 45 columns**, including 56,000 normal rows and 119,341 attack rows. The G1 audit inferred 30 integer, 11 decimal, and four text columns and found zero empty or whitespace-only cells. UNSW’s official test file has 82,332 records and the same ordered header. The binary `label` provides the target (`0` normal, `1` attack). Excluding `id`, `label`, and `attack_cat` leaves **42 predictors**. The category label is retained separately for analysis. [G1 dataset analysis](research/level-1/DATASET_ANALYSIS.md) · [UNSW dataset documentation](https://research.unsw.edu.au/projects/unsw-nb15-dataset)

### Repeated and ambiguous observations

| G1 check | Result |
| --- | --- |
| Identical records after removing `id` | 107,740 distinct records and 67,601 occurrences beyond the first |
| Exact raw predictor vectors | 101,040 distinct vectors and 74,301 occurrences beyond the first |
| Predictor groups with both binary labels | 229 groups containing 940 rows, including 396 normal and 544 attacks |

Within a conflicting group, the model receives the same predictors for different labels. The available fields cannot establish the cause. Fuzzers accounts for 543 of the 544 affected attack rows. A hypothetical removal of exact repeated records excluding `id` would lower the attack share from 68.06% to 51.84%. The experiments retain all records and original labels so these changes in category and class representation are avoided. [G1 dataset analysis](research/level-1/DATASET_ANALYSIS.md)

### Feature handling

The scikit-learn `Pipeline` contains a `ColumnTransformer`. `OneHotEncoder(handle_unknown="ignore")` encodes `proto`, `service`, `state`, and `is_ftp_login`. The literal `service = "-"` remains a category. It occurs in 94,168 training records, and its precise meaning in the prepared partition remains unverified. The 22 nonbinary FTP login codes (six `2`s and sixteen `4`s) remain categories alongside `0` and `1`. Numeric predictors use `StandardScaler`. Training-time transformations are fitted separately within each training subset and reused on its validation subset. [G1 dataset analysis](research/level-1/DATASET_ANALYSIS.md) · [G2 preprocessing](research/level-1/BASELINE_RESULTS.md#method) · [scikit-learn guidance on preprocessing and leakage](https://scikit-learn.org/1.7/common_pitfalls.html#data-leakage)

## 4. Validation and model selection

### Group-aware validation

G2–G4 used the official training file for model development. Three shuffled `StratifiedGroupKFold` outer splits (seed 42) assigned identical tuples of raw predictor values to the same group, including the groups with conflicting labels. Each training/validation pair verified zero group overlap. Stratification attempts to preserve class ratios while respecting these groups. It controls exact duplicate leakage within cross-validation, with near-duplicates and related flows outside the grouping definition. [G2 fold audit](research/level-1/BASELINE_RESULTS.md#fold-composition-and-group-isolation) · [scikit-learn StratifiedGroupKFold](https://scikit-learn.org/1.7/modules/generated/sklearn.model_selection.StratifiedGroupKFold.html)

G3 and G4 explored decision thresholds within the outer training subsets only. Three inner group-aware folds (seed 43) generated out-of-fold attack scores from separately fitted pipelines. For each candidate budget, the selection rule maximized inner attack recall subject to the false-positive budget, breaking ties by lower false-positive rate and then higher threshold. The selected threshold was fixed before scoring the corresponding outer validation fold. Tuned thresholds treated ties as positive (`score >= threshold`). The default labeled a record as an attack when its score was strictly above 0.5. [G3 threshold methodology](research/level-1/THRESHOLD_ANALYSIS.md) · [G4 model comparison](research/level-1/MODEL_COMPARISON.md)

### Results on the training partition

G2’s majority-class dummy predicted every row as attack, yielding 100% attack recall, 100% false-positive rate, and 50% balanced accuracy. Logistic regression demonstrated how uninformative the dummy’s perfect recall was by detecting nearly as many attacks with many fewer false alarms. G4 evaluated logistic regression and the 48-tree forest on the same outer folds. The table pools one prediction per training record from the fold where it was held out. [G2 baseline](research/level-1/BASELINE_RESULTS.md) · [G4 metrics](research/level-1/MODEL_COMPARISON.md#default-threshold-comparison)

| Model at threshold 0.5 | Accuracy | Balanced accuracy | Precision | Attack recall | F1 | False-positive rate | ROC AUC | Average precision |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Logistic regression | 93.515% | 90.524% | 92.223% | 98.803% | 95.400% | 17.755% | 0.9840 | 0.9916 |
| Random Forest | 94.721% | 92.391% | 93.743% | 98.840% | 96.224% | 14.059% | 0.9912 | 0.9958 |

G3/G4 also compared recall at similar *observed* false-positive rates. At the inner 5% budget, logistic regression achieved 89.455% recall at 5.021% pooled outer FPR and the forest achieved 93.647% recall at 4.950% FPR. Each met the 5% cap on one of three outer folds. At the inner 10% budget, logistic regression achieved 94.586% recall at 9.932% FPR and the forest achieved 97.228% recall at 10.046% FPR. Logistic regression met the 10% cap on two folds and the forest met it on one. These differences show that inner budget compliance can fail to carry over to unseen folds. [G3 threshold results and curves](research/level-1/THRESHOLD_ANALYSIS.md) · [G4 operating point comparison](research/level-1/MODEL_COMPARISON.md#recall-at-comparable-observed-false-positive-rates)

The forest reduced false positives from 9,943 to 7,873 at 0.5, with similar attack recall and better ranking metrics. It took 126.902 seconds to fit across the three folds and 5.165 seconds to score their validation batches. Logistic regression took 32.334 and 3.016 seconds, respectively. The serialized fold pipelines averaged 2,978,016 bytes for the forest and 6,035 bytes for logistic regression. These are local experiment timings. The forest was selected for its improved detection trade-off, while its one-worker configuration and artifact size kept it usable in the local application. One configuration and one split seed limit the strength of the comparison. [G4 measured costs and recommendation](research/level-1/MODEL_COMPARISON.md)

### Frozen model

G5 fitted `unsw-nb15-rf-v1` on all 175,341 official training records. The forest uses 48 trees, seed 42, a maximum depth of 14, up to 512 leaves per tree, at least five samples per leaf, bootstrap draws of 75% of the fitting subset, square-root feature sampling at splits, and one worker. The package stores the fitted preprocessing and estimator together, alongside a manifest with the ordered feature schema, file fingerprints, parameters, classes, dependency versions, and threshold of 0.5. The recorded fit and G10 run used Python 3.12.3 and scikit-learn 1.7.2. The application loads this local package at startup and applies it directly at inference time. [G5 package and prediction contract](MODEL_PACKAGING.md) · [G10 freeze record](FINAL_MODEL_EVALUATION.md#frozen-configuration)

## 5. System architecture and implementation

| Component | Responsibilities |
| --- | --- |
| React, TypeScript, and Vite | Overview, alert search and detail, incident management, analyst notes, manual JSON and CSV analysis |
| FastAPI and Pydantic | Request validation, bounded CSV uploads and JSON batches, model metadata, prediction and investigation APIs |
| Python and scikit-learn | Shared predictor schema, type checking, packaged preprocessing, class and attack score generation |
| PostgreSQL, SQLAlchemy, Psycopg, and Alembic | Versioned schema, prediction batches, suspected alerts, incidents, notes, and transactional persistence |

The dashboard communicates with FastAPI through Vite’s same-origin `/api/` proxy. FastAPI owns the model package and database connection. `GET /health` indicates API availability independently of database operations. The overview derives counts and the chart from alert responses. Incidents are discovered through linked alerts, consistent with the implemented API. [Architecture diagrams](ARCHITECTURE.md) · [Dashboard setup](DASHBOARD_SETUP.md) · [Database API](DATABASE_SETUP.md#database-and-api-behavior)

1. **Validate and preview.** `POST /csv/preview` validates a UTF-8 CSV with up to 1,000 records and 2 MiB of content. The server requires all 42 predictors, strips optional metadata columns, and returns validated records for preview.
2. **Score.** The browser calls `POST /predict` in batches of up to 100. The service returns one label and attack probability per record. The dashboard shows progress, class totals, and record details. Manual JSON uses the same inference contract. Prediction makes no database writes.
3. **Save.** An explicit user action calls `POST /analyze`. The backend scores each batch with the same inference module and commits the batch and its suspected-attack alerts together. Each alert records a batch reference, record index, and attack probability. The batch supplies the model version, threshold, and prediction time.
4. **Investigate.** The analyst selects one or more unassigned alerts, creates an incident, moves it through `open`, `investigating`, and `resolved` states as appropriate, and adds notes. Unassigned alerts appear as `unreviewed`. The author field is supplied by the user. [Dashboard CSV workflow](DASHBOARD_SETUP.md#upload-and-analyze-csv) · [Database API](DATABASE_SETUP.md#database-and-api-behavior)

Persistence retries use an idempotency key with a stored request digest. The CSV client derives a repeatable key from the ordered predictors and batch position. A matching replay returns the original receipt and alert IDs. A different batch using the same key receives HTTP 409. The database enforces key uniqueness across concurrent writers. The transaction boundary is one batch, so successfully persisted batches can be recovered through retries after a later batch fails. [Dashboard CSV workflow](DASHBOARD_SETUP.md#upload-and-analyze-csv) · [Idempotency contract](DATABASE_SETUP.md#database-and-api-behavior)

## 6. Official held-out evaluation

G10 verified the frozen model, ordered schema, training fingerprint, and threshold before scoring. Its audit of tracked source, Git history, and recorded runs found that G1 had checked test CSV structure, while model development and threshold exploration used the training partition. The final evaluator loaded the G5 package and scored all 82,332 official test rows without fitting or changing the threshold. The test mix was 37,000 normal and 45,332 attack records. G4 figures below came from three separate fits on training subsets. G10 figures came from the single frozen fit on the complete training partition. [Final evaluation protocol](FINAL_MODEL_EVALUATION.md)

| Metric at threshold 0.5 | G4 pooled training validation | G10 official test |
| --- | ---: | ---: |
| Accuracy | 94.721% | 84.895% |
| Balanced accuracy | 92.391% | 83.268% |
| Attack precision | 93.743% | 78.767% |
| Attack recall | 98.840% | **99.347%** |
| F1 | 96.224% | 87.868% |
| False-positive rate | 14.059% | **32.811%** |
| ROC AUC | 0.9912 | 0.9824 |
| Average precision | 0.9958 | 0.9869 |

| Actual class | G4 predicted normal | G4 predicted attack | G10 predicted normal | G10 predicted attack |
| --- | ---: | ---: | ---: | ---: |
| Normal | 48,127 | 7,873 | 24,860 | 12,140 |
| Attack | 1,384 | 117,957 | 296 | 45,036 |

Recall divides true attack predictions by all attack rows. Precision divides true attack predictions by all attack predictions. F1 is their harmonic mean, and balanced accuracy averages attack recall and normal specificity. The false-positive rate divides false alarms by all normal rows. ROC AUC and average precision summarize score ranking over thresholds. G10 recall rose by 0.51 percentage points from G4 while the false-positive rate rose by 18.75 points. The fixed G10 operating point generated about 328 false alarms per 1,000 normal benchmark rows. [Final evaluation metrics and interpretation](FINAL_MODEL_EVALUATION.md#official-test-results)

### Category errors and exact overlap

The binary model missed 296 attacks. Fuzzers accounted for 285 of those misses, giving that category 95.299% recall across 6,062 records. Exploits accounted for eight misses, Reconnaissance for two, and Shellcode for one. There were zero observed misses in the other five attack categories, including Worms, which had 44 test records. These are binary detection rates grouped by the true attack category. Small counts limit what those rates say about other traffic in the same category. [Full attack-category counts](FINAL_MODEL_EVALUATION.md#attack-category-analysis)

The published partitions shared **1,302 distinct raw predictor vectors**, covering **8,541 test rows (10.374%)** and 10,279 training rows. The complete official results include all test records. Among the 73,791 test rows without an exact match, attack recall was 99.258% and the false-positive rate remained 32.735%. This subgroup is descriptive because the matching and nonmatching records differ in class mix. The overlap audit compares exact raw strings, so it leaves near-matches and alternative numeric spellings unmeasured. The official split was held out from model development, with this measured duplication limiting its independence as a test of unseen inputs. [G10 overlap audit](FINAL_MODEL_EVALUATION.md#exact-predictor-overlap)

## 7. Local security, reliability, and reproducibility

G11 verified loopback listeners for the local setup. PostgreSQL uses `127.0.0.1,::1`, FastAPI uses `127.0.0.1:8001`, and Vite serves on `127.0.0.1:5173`. The served API applies loopback host validation and the dashboard uses same-origin proxying. The application assumes a trusted local machine and operator. A local process able to reach the API can query or modify investigations, and client-supplied note authors are unverified. [G11 local access boundaries](RELIABILITY_TESTING.md#local-access-boundaries)

The backend enforces byte and record limits independently of the UI. It counts received bytes for CSV and JSON writes, including when the request omits its length. It rejects unsupported media types, malformed JSON or CSV, and missing, extra, malformed, or nonfinite predictor values. SQLAlchemy uses bound parameters and hides SQL parameters in error output. Database errors return a generic 503. Transaction rollback covers batch and alert writes, while locks protect competing incident assignments. A missing or incompatible model package fails startup. Only locally generated, trusted pickle artifacts belong in that package directory, because deserialization can execute code. [G11 failure and integrity coverage](RELIABILITY_TESTING.md#failure-and-integrity-coverage) · [scikit-learn model persistence](https://scikit-learn.org/1.7/model_persistence.html)

G11 recorded 71 passing Python tests, 22 passing frontend tests, and a successful TypeScript check and Vite production build. PostgreSQL integration tests applied migrations to fresh schemas in the separate test database. They verified concurrent replay, rollback, and persistence through a restart. The recorded Edge run used four synthetic records to save two suspected alerts, replay the same batch without duplicate alerts, update an incident, and retrieve its note. It also exercised invalid-file feedback, an injected 503 recovery, and keyboard navigation at a mobile viewport. [Reliability test record](RELIABILITY_TESTING.md)

The repository provides dependency specifications, migration code, training and evaluation commands, and synthetic demonstration inputs. Each reviewer provisions local PostgreSQL credentials and obtains the two prepared benchmark files from UNSW as needed. The runtime uses a trusted local model package produced by the documented G5 procedure. Credentials, downloaded CSVs, and generated model files stay outside Git. G10 documents fingerprints for the exact benchmark inputs and model used in the reported evaluation. [Database setup](DATABASE_SETUP.md) · [Model build and checksums](MODEL_PACKAGING.md) · [G10 evaluation reproduction](FINAL_MODEL_EVALUATION.md#reproduce-the-evaluation)

## 8. Limitations and Level 2 research

- **Representativeness.** The results describe one prepared cyber-range benchmark. Operational traffic patterns, prevalence, and drift can change precision and alert volume. The 32.81% benchmark false-positive rate is already a substantial burden for triage. High recall and ranking metrics on this benchmark cannot establish a manageable alert workload on a real network.
- **Evaluation design.** Exact grouping addresses one leakage mechanism within training validation. The official test still shares some exact vectors with training, and correlated flows, alternative numeric encodings, and capture-specific feature patterns may affect independence. The score has no demonstrated operational calibration. There was no test-driven threshold adjustment or model selection in Level 1.
- **Feature availability.** The 42-input schema depends on particular flow definitions and aggregates. Live traffic and network-log sources need a validated mapping of fields, units, time windows, direction, and missing values. The application has no evidence that raw logs or arbitrary flow summaries satisfy this contract.
- **Application scope.** The prototype has no authentication or role-based access and demonstrates a single-machine investigation workflow. Synthetic demonstration detections are real database entries when saved, and contribute to the dashboard’s alert counts. The stored alert records have no per-record source label. [G10 limitations](FINAL_MODEL_EVALUATION.md#limits-and-interpretation) · [G11 local access boundaries](RELIABILITY_TESTING.md#local-access-boundaries) · [Dashboard workflow](DASHBOARD_SETUP.md#dashboard-workflows)

Level 2 can address these gaps through separately versioned experiments. Additional datasets with documented feature definitions and independent capture splits can test transfer and false alarms more directly. Multiclass detection would require a separate target and evaluation with per-category support, macro F1, and confusion counts, especially for rare categories. Explainability work can assess global feature importance on held-out validation data and add individual alert explanations with checks for stability and correlated predictors. A Rust ingestion component can validate structured offline events against a versioned schema. Network-log integration should validate feature equivalence and coverage with an authorized offline sample before any scoring claims. [Level 2 roadmap](research/level-2/LEVEL_2_ROADMAP.md)
