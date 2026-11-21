# Planned Level 2 improvements

Level 2 extends the completed local Level 1 workflow. The priorities below are proposed for future work. Keep `unsw-nb15-rf-v1` and the [G10 official test report](../../FINAL_MODEL_EVALUATION.md) as a fixed reference.

## 1. Evaluate additional datasets

Start with a dataset audit. CICIDS2017 is one candidate because its publisher provides labeled flow CSVs. Record the version, redistribution terms, capture context, labels, feature definitions and known data issues before deciding whether it supports an external comparison. [Canadian Institute for Cybersecurity dataset page](https://www.unb.ca/cic/datasets/ids-2017.html)

- Compare feature semantics before comparing models. Document units, direction, aggregation windows and missing fields. If the frozen model's inputs cannot be reproduced, define a supported feature schema and evaluate a separately versioned model.
- Reserve independent evaluation data before developing or tuning a candidate. Within development splits, keep identical predictor vectors together. Where reliable capture or session metadata is available, hold out entire relevant capture periods or environments to test transfer.
- Agree on an acceptable false-positive budget for the intended use and select an operating point using development data only. Freeze the model, schema and threshold before scoring a new held-out set. Report attack recall, false-positive rate and denominators for each independent test context. Use G10 as a historical benchmark.

## 2. Assess multiclass attack classification

Audit attack labels and per-category sample counts in development data. Define how to handle rare and ambiguous labels, then test a classifier that distinguishes attack categories alongside the existing binary baseline. Evaluate per-class precision, recall and support, macro F1 and the confusion matrix with grouped splits. Keep an explicit path for uncertain classifications so the analyst can review those cases without relying on a category the model cannot support.

## 3. Explain model predictions

Evaluate a tree-based feature attribution method on the saved Random Forest as a starting point. Check how one-hot encoded values roll up to human-readable features and whether the explanation is credible across representative normal, detected and misclassified records. If the explanation requires reference data, construct it from development data. Measure explanation stability and runtime before exposing it in the dashboard. Describe the displayed contributions as associations with the score and leave incident conclusions to the analyst.

## 4. Prototype Rust ingestion and network-log integration

1. Prototype a bounded Rust parser for offline CSV or structured network logs. Validate record size, field types and malformed values. Compare its outputs to Python on the same synthetic fixtures and measure throughput and resource use before adding it to the application.
2. Define a versioned mapping for one log format on permitted offline samples. Zeek's `conn.log` is a candidate input. Inspect example fields such as connection duration and originator/responder byte counts for precise units, direction and availability. Document which UNSW-NB15 features need additional sources or history and which are unavailable. [Zeek connection log reference](https://docs.zeek.org/en/current/reference/logs/conn.html)
3. Validate the mapper against reference fixtures and measure missing-field and rejection rates on a separate sample. If critical features cannot be derived reliably, use the supported feature schema and separately evaluated model described above. Assess that pipeline on fresh labeled records before presenting any live-network results.
