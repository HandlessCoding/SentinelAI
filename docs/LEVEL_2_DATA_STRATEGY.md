# G13 · Level 2 data and model strategy

## Recommendation

Build a **separate, versioned flow-feature pipeline** for Level 2. Start with
a small set of fields whose semantics can be verified across flow exporters.
Use standalone University of Queensland (UQ) NetFlow components for the
first experiments, and reserve an entire capture campaign before collecting
development data. Keep the Level 1 dashboard, API, 42-feature input contract,
`unsw-nb15-rf-v1` package, and G10 report as the reproducible Level 1 reference.
G13 covers research and planning. No datasets were downloaded and no models
were trained.

The existing pipeline groups exact raw predictor tuples before splitting and
fits preprocessing inside each training fold. The threshold experiment uses
inner predictions to choose a threshold. Packaging records the ordered
schema, dependencies, threshold, and training
fingerprint. Retain these practices. Several Level 1 inputs, including
`ct_*` history features and FTP and HTTP fields, depend on the benchmark's
feature extraction. The current loader also enforces the exact version,
schema, runtime, and artifact digest. A second contract avoids forcing
other flow sources into those 42 fields. [G2 pipeline](../ml/run_baseline.py) · [G3 threshold runner](../ml/run_threshold_analysis.py) · [G5 packaging](../ml/train_model.py) · [Level 1 inference](../ml/inference.py) · [Level 2 roadmap](LEVEL_2_ROADMAP.md)

G4's pooled training-only validation recorded **98.84% attack recall and
14.06% false-positive rate (FPR)** at 0.5. At its exploratory 5% operating
point, the forest achieved 93.65% recall and a pooled 4.95% FPR, while
meeting that budget on one of three outer folds. G10 recorded **99.35%
recall and 32.81% FPR** on the official test, with 8,541 test rows sharing
exact predictors with training. These historical results motivate measuring
false alarms on each new context. G10 scores, CSV, and derivatives of
the same UNSW captures are outside Level 2 model development. [G4 comparison](MODEL_COMPARISON.md) · [G10 final evaluation](FINAL_MODEL_EVALUATION.md)

## Dataset comparison

Sizes below distinguish publisher or author figures from **local disk
planning allowances**. GB is decimal and GiB is binary. Row and field counts
refer to the named release. For a future acquisition, verify the exact file,
compressed and expanded bytes, checksum, header, and access terms before
allocating storage.

| Candidate | Coverage and schema | Table size and working space | Recommended role |
| --- | --- | --- | --- |
| Expanded UNSW-NB15, four original CSVs | 2,540,044 records from the same UNSW cyber-range collection as the prepared Level 1 partitions. The publisher describes a 49-field feature/label release with Argus, Bro, and derived fields. The nine attack categories are Analysis, Backdoors, DoS, Exploits, Fuzzers, Generic, Reconnaissance, Shellcode, and Worms. Validate the data dictionary and header before counting eligible predictors. | About **0.55 GB** for the original tabular corpus in Sarhan et al.'s comparison. Allow **2–3 GiB** for raw tables, normalized output, and scratch. UNSW separately reports about **100 GB** of packet captures, outside the plan. | Historical data audit only if needed. Extra rows can add within-corpus coverage. The shared capture lineage disqualifies this corpus and NF-UNSW derivatives as independent confirmation of Level 1. Exclude that lineage from the Level 2 pilot. [UNSW release and terms](https://research.unsw.edu.au/projects/unsw-nb15-dataset) · [Reported CSV size](https://arxiv.org/html/2101.11315#S3.T2) |
| CIC-IDS2017 | About **2.83 million** original flows from five days in one lab. The original `MachineLearningCSV` has **79 columns including label**, omitting protocol and timestamp. The fuller `GeneratedLabelledFlows` export has 85 columns including label. Original labels cover 14 attack types plus benign, including brute force, DoS/DDoS, web attacks, infiltration, bots, port scans, and Heartbleed. | The correction authors list `CICIDS2017_improved.zip` as **328M** compressed. Exact original archive and corrected expanded sizes are unverified here. Allow **3–5 GiB** for one corrected release, extraction, and scratch. Use flow tables only. | Conditional cross-export stress test on a separately frozen compatible feature subset. The original and corrected versions share one capture lineage. [UNB release and terms](https://www.unb.ca/cic/datasets/ids-2017.html) · [Archive schema comparison](https://fenix.tecnico.ulisboa.pt/downloadFile/1689244997263067/82014-joao-meira_dissertacao.pdf) · [Original empirical counts](https://pmc.ncbi.nlm.nih.gov/articles/PMC10089481/) · [Corrected archive listing](https://intrusion-detection.distrinet-research.be/CNS2022/Datasets/) |
| NF-UQ-NIDS v1 and v2 | **11,994,893** flows in v1 and **75,987,976** in v2. Both combine NetFlow exports of UNSW-NB15, CSE-CIC-IDS2018, ToN-IoT, and BoT-IoT. UQ lists 12 v1 flow fields including four endpoint address/port fields and 43 v2 fields before predictor exclusions. V2 has counters and timing, plus fields such as flags, TTL, and retransmission. The v2 merge normalizes original labels into 20 attack labels, with DoS/DDoS dominant and rare groups such as Worms. V3 adds ten temporal fields in standalone exports of the same source corpora. | Published expanded CSVs are **1.0 GB** (v1) and **12.5 GB** (v2). The three proposed standalone v2 components together are **10.87 GB** of CSV. Allow **20–30 GiB** on `D:` if all three are later approved, and avoid storing the merge alongside them. | Prefer one standalone v2 development component first. Its common schema gives a practical start for comparing distinct captures with the same exporter. V1 is a smaller pre-training fallback, while v3 is a metadata candidate if v2 lacks usable grouping fields. [UQ releases and label counts](https://staff.itee.uq.edu.au/marius/NIDS_datasets/) · [Feature and size tables](https://arxiv.org/html/2101.11315#S3.T2) · [V3 paper](https://arxiv.org/abs/2503.04404) |

### Access terms and label quality

- **UNSW-NB15.** UNSW permits academic research use with the five citations
  named on its page. Commercial use calls for agreement with the authors.
  The tabular features and labels come from controlled captures. The Level 1
  duplicate and conflicting-label audit applies to the prepared release.
  A future expanded release audit would need its own counts and evidence.
  [UNSW terms](https://research.unsw.edu.au/projects/unsw-nb15-dataset) · [G1 dataset audit](DATASET_ANALYSIS.md)
- **CIC-IDS2017.** UNB makes the data available for research and requests its
  paper citation. Its page provides no explicit redistribution terms for
  SentinelAI. Monday is benign-only, and scheduled scenarios can make day,
  timestamp, and host identity proxies for the target. Engelen et al.
  documented flow construction, feature extraction, and label problems.
  Liu et al.'s corrected release distinguishes flows intended as attacks
  that show no malicious behavior. If this corpus is used, preregister
  `Attempted` as benign following the correction authors' recommendation,
  report a separate sensitivity slice, and exclude that field from
  predictors. Confirm terms for the particular corrected release too.
  [UNB terms and schedule](https://www.unb.ca/cic/datasets/ids-2017.html) · [Dataset paper](https://doi.org/10.5220/0006639801080116) · [Engelen et al. audit](https://intrusion-detection.distrinet-research.be/WTMC2021/index.html) · [Liu et al. label guidance](https://intrusion-detection.distrinet-research.be/CNS2022/Dataset_Download.html)
- **UQ NetFlow.** The release terms permit cited academic research. Commercial
  use calls for author agreement. Check the exact component and underlying
  terms before acquiring or sharing derived rows. The researchers matched
  reconstructed flows against source attack records and assigned unmatched
  flows to benign, so data quality depends on the matching and the original
  labels. The source mixture is uneven. BoT-IoT-v2 is about 99.6% attack, so
  a pooled score can mask weak performance on benign traffic from specific
  sources. A shared exporter helps with schema consistency while leaving
  capture and labeling differences in place. [UQ release terms](https://rdm.uq.edu.au/files/e2412450-ef9c-11ed-827d-e762de186848) · [Reconstruction and label method](https://arxiv.org/html/2101.11315#S3.SS2)

Keep source and normalized files, acquisition manifests containing sensitive
details, predictions on external records, and fitted artifacts local and
Git-ignored. Publish source URLs, non-sensitive provenance, schema and split
definitions, checksums when permitted, synthetic fixtures, and aggregate
results. Share data only with explicit permission covering the selected
release and use.

For the first v2 component, budget **6–8 GiB** for the data, an output copy,
and scratch space. If storage changes the plan before any scoring, the
analogous three v1 components total **0.72 GB** of CSV, with a narrower
feature set and different row populations. Reserve the same parent
campaign in either version. [Published storage comparisons](https://arxiv.org/html/2101.11315#S3.T2)

## Portable feature contract

Define a versioned bidirectional flow schema for the Python experiment and
a future Rust adapter. Its minimum candidates are the IANA transport protocol
number, duration in integer milliseconds, packet counts, and IP octet
counts. Use directional counts only when start orientation is
reproducible across adapters. If two exporters disagree on direction,
consider a consistently defined total or exclude the field before training.
Record each field's types, units, rounding, direction, observation point,
flow timeout and record boundaries, and treatment of sampling and missing
values. Keep a list of accepted protocol mappings.
[IPFIX element definitions](https://www.iana.org/assignments/ipfix) · [IPFIX biflow direction](https://www.rfc-editor.org/rfc/rfc5103.html#section-5)

Treat the nProbe mappings as candidates pending release checks. Zeek's
`orig_ip_bytes` includes IP headers, while `orig_bytes` counts payload
bytes. CICFlowMeter's directional length sums use payload byte statistics,
so they cannot substitute for IP octets. Flow timeout, duration, and packet
count conventions also require parity checks. Verify the exporter version
and selected configuration, and run small shared fixtures through Python
and Rust before claiming compatibility. If CIC cannot supply the frozen
fields, reserve it for a separate compatibility study with a predeclared
portable schema. [nProbe field definitions](https://www.ntop.org/guides/nprobe/flow_information_elements.html) · [Zeek connection fields](https://docs.zeek.org/en/current/scripts/base/protocols/conn/main.zeek.html#type-Conn::Info) · [CICFlowMeter implementation](https://github.com/ahlashkari/CICFlowMeter/blob/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java)

Keep raw addresses, ports, session identifiers, absolute timestamps, source
and exporter identifiers, binary targets, and attack categories off the
initial predictor list. Retain permitted provenance locally for grouping
and reporting. Defer application-specific fields, TCP flags, and temporal
expansions until they have a reproducible definition. Reject unsupported
inputs with a recorded reason. A missing value needs an explicit policy
and cannot stand for a measured zero. Keep original subtype labels for
auditing. Normalize only the benign/attack target for the pilot and
preregister any ambiguous label mappings. [Cross-dataset feature study](https://arxiv.org/html/2104.07183v2)

## Leakage-safe evaluation plan

1. **Reserve whole sources before development.** Start with standalone
   **NF-ToN-IoT-v2** (16,940,496 rows, about 2.47 GB CSV). Consider standalone
   **NF-BoT-IoT-v2** (37,763,497 rows, 5.60 GB) as a second development source
   after checking the metadata and footprint. Hold out all of the standalone
   **NF-CSE-CIC-IDS2018-v2** campaign (18,893,708 rows, 2.80 GB).
   The CSE-CIC 2018 capture is distinct from CIC-IDS2017 and the proposed
   development captures. Withhold its benign and attack flows, raw exports,
   corrected versions, all NetFlow versions, and merges that contain it.
   Lock the holdout file and provenance before training. Keep the records
   and labels outside experiment scripts until the evaluation is authorized.
   A public holdout tests transfer to a separate capture with the same
   reconstruction tool. Plan a second confirmation on a newly collected or
   separately supplied authorized capture from a different site or period,
   with trustworthy ground truth independent of the model. A benign-only
   capture can estimate FPR. Attack recall requires verified attack examples
   from the independent context. [UQ components](https://staff.itee.uq.edu.au/marius/NIDS_datasets/) · [CSE-CIC-IDS2018 origin](https://www.unb.ca/cic/datasets/ids-2018.html) · [Cross-source evaluation study](https://arxiv.org/abs/2205.04112)
2. **Audit before splitting.** Identify capture, day, and event or session
   groups using released metadata. Assign each capture derivative to its
   parent campaign. Check units, nonfinite values, missing fields, class
   support, and duplicates including canonical typed predictor tuples
   after deterministic normalization and before learned transformations.
   Keep conflicting labels visible and in the same group. Group related
   flows and exact vectors together across development folds, using
   connected groups if those constraints intersect. Do not infer sessions
   or timestamps from CSV row order. V2's released flow fields lack session
   IDs and start times. If verified metadata or enough viable groups are
   unavailable, use valid whole-source splits with sufficient sources,
   investigate provenance in v3, or pause model selection. With only two
   whole-source development groups, a nested holdout protocol lacks enough
   independent groups. V3 derived from the held-out campaign stays reserved.
3. **Select on development groups only.** Use source- or capture-held-out
   outer folds and group-aware inner folds. Stratify where feasible, and
   check for zero shared capture/session groups and canonical predictor
   groups between each pair of training and validation folds. Report folds
   with insufficient normal or attack support. Fit scaling, encoding, any
   imputation, weighting or resampling, calibration, and feature decisions
   inside the permitted fit splits. Keep natural class prevalence in
   validation and holdout. Choose a deterministic threshold that maximizes
   inner attack recall subject to the FPR budget. If none with positive
   detections meets it, record the budget as infeasible. Freeze the chosen
   final pipeline, comparator, and thresholds after setting thresholds and
   any calibration on disjoint development groups scored by the fixed fit.
   [Grouped splits](https://scikit-learn.org/1.7/modules/cross_validation.html#cross-validation-iterators-for-grouped-data) · [Threshold selection](https://scikit-learn.org/1.7/modules/classification_threshold.html)
4. **Evaluate once under the frozen plan.** Record and verify file hashes,
   schema, model parameters, library versions, seeds, thresholds and tie
   rules, split manifests, and reporting rules. Compare source/session
   lineage and canonical-vector overlap before scoring. Known shared source
   material invalidates the independent split. Identical simple feature
   tuples can also occur in unrelated captures. Report the overall and
   exact-match-free slices without editing the reserved records or using
   either slice for selection. Report all declared results, including failed
   gates. Once reviewed, use a fresh independent capture to confirm future
   changes.

## Candidates and success criteria

Start with a majority-class sanity check, regularized Logistic Regression,
and a bounded Random Forest. Keep the first forest small and single-worker,
with a fixed seed and bounded depth and leaves. Compare a fixed
single-source forest with its multi-source equivalent using the same
features, validation groups, and training budget where feasible. That
comparison estimates the value of source diversity. Optionally add a modest
histogram gradient boosting candidate after the baselines fit the resource
budget. Restrict search and any training-only sampling to development.
Rerun comparisons on identical eligible records and report the sampling
rule, class weights, timing, and memory. Freeze the single-source bounded
forest as the same-schema reference alongside the candidate. Set its threshold using the same
development FPR budget. G4 and G10 used different inputs from the proposed
schema, so a direct performance gain requires a paired comparison on the
same new holdout.

| Proposed research criterion | Evidence required |
| --- | --- |
| **Primary operating point** | On each evaluable independent context, FPR among scored benign flows **≤10%** and end-to-end attack recall **≥95%** at one frozen operating point. |
| **Stretch operating point** | FPR **≤5%** with attack recall **≥95%**, measured only if this second threshold was frozen on development data. |
| **Improvement at comparable detection** | Against the frozen same-schema reference on the same holdout, at least **2 percentage points lower FPR** with at most **2 points lower recall**, alongside the absolute primary gates. Report the paired difference and its uncertainty. |
| **Input coverage** | Aim for at least **95%** of in-scope records scoreable per source and per class where support permits. Report coverage and rejection counts by source and class. Count rejected attacks as missed in end-to-end recall and also report recall for scored records. |
| **Reproducibility** | Repeatable splits and decisions from fixed manifests and seeds. Python and future Rust adapters produce the same canonical records and rejection outcomes for the shared fixtures. |

These thresholds are proposed project goals and need approval before data
acquisition. Report raw confusion counts, attack and benign denominators,
precision, F1, balanced accuracy, average precision, ROC AUC, and false
alerts per 1,000 benign flows. Indicate which scores use only eligible
records and account separately for rejected records. Report results by
source, capture and attack family where supported, alongside the pooled values. Where enough
independent captures or scenario blocks exist, compute 95% uncertainty
intervals by resampling those blocks, pairing comparators on the same
blocks. Assess whether the intervals support meeting the gates and the
comparison margin. With too few independent groups or wide intervals,
present point estimates as preliminary. Benchmark FPR does not establish
operational alert volume, which also depends on input prevalence and
coverage.

## Implementation order after approval

1. Approve the candidate list, primary and stretch gates, and the holdout
   reservation. Check disk space and exact release terms. Write a small
   schema and provenance audit using synthetic fixtures only.
2. Obtain approval for a single development flow table. Record source,
   filename, bytes, digest, exporter and label versions, class mapping,
   and capture lineage locally. Stream the audit from `D:` and profile
   peak memory and disk. Acquire a second development source only after
   the audit confirms the need and the remaining space. Keep the holdout
   outside the development workspace.
3. Confirm which groups and feature mappings are supportable, then implement
   separate offline adapters, split checks, baseline experiments, and
   threshold selection. If provenance, feature parity, or label support
   is insufficient, resolve that before training or revise the development
   plan without accessing the holdout.
4. Freeze the candidate and run the separately authorized holdout
   evaluation. Use the outcome to report what generalized and where errors
   remain. Plan the Rust ingestion and approved independent-site validation
   against the frozen contract before promoting a Level 2 model into the
   application.
