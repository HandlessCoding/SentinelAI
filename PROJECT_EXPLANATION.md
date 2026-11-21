# How SentinelAI works

SentinelAI Level 1 takes rows of prepared network-flow features, scores them for suspected attacks, and lets an analyst save and investigate the results. A row describes a network record through measurements such as protocol, service, duration, and counters. The demonstration starts with those measurements already prepared.

## Follow one record through the application

1. Open **Analyze → CSV upload** and choose the bundled synthetic CSV. The React dashboard sends it to FastAPI. The API checks its headers and values and returns valid predictor records for preview. It checks for all 42 predictors and drops the optional `id`, `label`, and `attack_cat` fields. [Synthetic CSV](examples/unsw_nb15_inference.csv)
2. Select **Analyze CSV**. The dashboard sends the validated records in batches of at most 100. The saved model transforms and scores each record. The dashboard displays the score, its normal or suspected-attack classification, and totals for the upload. Manual JSON input uses the same prediction logic.
3. Select **Save suspected alerts** to store the results for investigation. FastAPI scores the submitted records itself. PostgreSQL records the batch and creates an alert for each suspected attack. Running predictions alone leaves the database untouched.
4. Open a saved alert and create an incident from it. Set the incident's status and add a note explaining what you would investigate. An alert represents a model's suspicion. An incident is the analyst's workspace for reviewing one or more alerts.

The dashboard guide gives the startup commands and click-by-click workflow. The architecture diagrams show where HTTP requests, predictions, and database writes occur. [Dashboard guide](docs/DASHBOARD_SETUP.md), [Architecture diagrams](docs/ARCHITECTURE.md)

## What the model learns

The official UNSW-NB15 training file supplies **features** and a **target**. Features are the 42 values given to the model. The binary `label` is the training target, with `0` for normal and `1` for attack. `id` identifies a row. `attack_cat` gives a more specific attack category and is available for analyzing benchmark results. Both metadata fields stay outside the predictor set, along with `label`.

The scikit-learn pipeline packages two stages together.

1. **Preprocessing** converts input values to the representation the classifier expects. It scales numeric features and uses one-hot encoding for `proto`, `service`, `state`, and `is_ftp_login`. One-hot encoding gives each learned category a separate indicator. The literal service `-` and codes such as FTP `2` and `4` remain distinct categories under this scheme.
2. **Classification** uses a Random Forest with 48 decision trees. Each tree uses learned tests on input features to estimate the attack class probability. The forest averages the trees' class probabilities. SentinelAI emits an attack prediction when this score is strictly above `0.5`. The score measures the model's estimate for the supplied features. Its calibration on live traffic remains unverified.

Training produces `pipeline.pkl` and `metadata.json` in the local ignored `artifacts/` directory. The fitted pipeline carries the learned transformations together with the forest. The metadata records the version, schema, threshold, training provenance, and runtime versions. FastAPI loads the trusted package once at startup. Inference applies the fitted model to records received afterward. [Dataset analysis](docs/DATASET_ANALYSIS.md), [Model packaging](docs/MODEL_PACKAGING.md)

## Why the experiments use groups

The training file contains identical sets of the 42 predictor values. If a random row split put one copy in training and another in validation, the evaluation would include inputs the model had already seen. SentinelAI assigned identical raw predictor vectors to the same group and used three `StratifiedGroupKFold` splits. The split tries to keep the class mix similar across folds while keeping each group intact. Each experiment checked that group overlap was zero between the relevant training and validation portions. The preprocessing was fitted within each training fold.

Some identical feature vectors have both normal and attack labels. The training analysis found 229 such groups. The experiments kept all rows and grouped these together. A classifier that receives only those 42 values cannot assign two different decisions to the same input. The available fields leave the reason for the conflicting labels unresolved. [Dataset group findings](docs/DATASET_ANALYSIS.md), [G2 validation design](docs/BASELINE_RESULTS.md)

The experiments advanced in four steps.

| Step | Question answered |
|---|---|
| G2 baseline | How much does logistic regression improve on always predicting the most frequent class? |
| G3 threshold exploration | How much recall can logistic regression retain at a target false-positive rate? Inner folds selected each threshold, and outer folds measured how it performed on unseen groups. |
| G4 model comparison | Does the Random Forest improve on logistic regression under the same group-aware outer splits? At the default threshold, the forest lowered the pooled false-positive rate from 17.76% to 14.06% while keeping attack recall about 98.8%. |
| G5 packaging | Can the selected forest and the preprocessing be saved and reused? The recorded run fitted the chosen configuration on all 175,341 training rows and packaged it as `unsw-nb15-rf-v1` with threshold `0.5`. |

The official test partition was reserved during model selection, threshold exploration, and packaging. G10 measured the frozen configuration on the published test split after those choices were complete. [G3 threshold analysis](docs/THRESHOLD_ANALYSIS.md), [G4 model comparison](docs/MODEL_COMPARISON.md), [G10 evaluation procedure](docs/FINAL_MODEL_EVALUATION.md)

## How to read the final results

At threshold `0.5`, the pooled G4 validation scores combine predictions from three models fitted to subsets of the training CSV. The G10 scores come from one frozen model fitted to the entire training CSV and measured on all 82,332 rows of the official test CSV.

| Metric | Training-only G4 validation | Official G10 test |
|---|---:|---:|
| Accuracy | 94.72% | 84.90% |
| Attack recall | 98.84% | 99.35% |
| False-positive rate | 14.06% | 32.81% |

**Attack recall** asks how many of the actual attacks the model flagged. G10 flagged 45,036 of 45,332 attack rows and missed 296. **False-positive rate** asks how many of the actual normal rows the model falsely flagged. G10 falsely flagged 12,140 of 37,000 normal rows, about 328 false alarms per 1,000 normal rows on that benchmark. **Precision** asks how many flagged rows were attacks. The official test precision was 78.77%, and it reflects the class mix of that partition.

The published partitions share 1,302 distinct exact raw predictor vectors, present in 8,541 official test rows. The model used only the published training file for fitting. The overlap was examined during G10 and remained in the official score. It limits how much of the benchmark represents entirely new predictor values. Among the test rows whose exact vector was absent from the training partition, the false-positive rate was still 32.735%. [G10 metrics and overlap audit](docs/FINAL_MODEL_EVALUATION.md)

## What to explain during the defense

- **Why choose the Random Forest?** G4 compared it with logistic regression on the same group-aware folds. At `0.5`, it reduced false positives, improved balanced accuracy, and retained similar attack recall. The frozen configuration has 48 trees and uses one worker. This was a decision made with training-only validation. [Model comparison](docs/MODEL_COMPARISON.md), [Packaged configuration](docs/MODEL_PACKAGING.md)
- **What does the browser demonstration prove?** The synthetic CSV demonstrates validation, batch scoring, record inspection, storage, and the analyst workflow. A saved synthetic alert is a real row in the local database, with a score from the real model. Dashboard totals represent saved alerts in that database. The model evaluation figures come from the official test file and are reported separately. [Dashboard workflows](docs/DASHBOARD_SETUP.md), [G10 results](docs/FINAL_MODEL_EVALUATION.md)
- **What happens if saving fails?** Prediction still works if PostgreSQL goes down while FastAPI and the model are available. The database operation returns a useful error. Completed batches remain saved. An unchanged retry reuses its batch keys and receipts, so it does not insert duplicate alerts for that submission. [Reliability verification](docs/RELIABILITY_TESTING.md)
- **Can it monitor a live network?** The current input is a prepared UNSW-NB15-format record. A live source would need a validated mapping that produces equivalent feature definitions and units, followed by testing on representative traffic. The test benchmark's 32.81% false-positive rate already shows why analyst workload and alert volumes need their own measurements. The current implementation is a loopback-only, trusted-user tool with no authentication. [Local access boundaries](docs/RELIABILITY_TESTING.md#local-access-boundaries), [Benchmark limitations](docs/FINAL_MODEL_EVALUATION.md#limits-and-interpretation)

The CSV client, FastAPI routes, and inference module show how one record moves through the implementation. The database guide covers local persistence and migration tests. [CSV client](frontend/src/CsvAnalysis.tsx), [Prediction routes](backend/routes.py), [Inference module](ml/inference.py), [Investigation routes](backend/investigations.py), [Database setup](docs/DATABASE_SETUP.md)
