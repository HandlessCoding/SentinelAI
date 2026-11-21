# G20 · Capture-aware dataset selection and ML validation strategy

## Recommendation

Use **IoT-23 v2 labeled Zeek connection logs** as the first source
to qualify for SentinelAI v2 development. Its named captures,
capture-specific documentation, and labeling rules support an
auditable split and a feature contract close to the intended
collector. The release is still marked as work in progress.
Qualify specific files, label evidence, original recording groups,
and usage terms before training. CTU-13 is a secondary, source-native
botnet experiment. A separately documented environment with mixed,
verified ground truth is still needed to test transfer.
[IoT-23 v2 publisher index](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/) · [CTU-13 publisher page](https://www.stratosphereips.org/datasets-ctu13/)

Capture-separated evaluation within IoT-23 v2 is plausible. A
four-role split with enough verified normal and malicious traffic
remains unproven. The eight benign files come from **three original
device captures**, so allocating a benign file to each role can
reuse the same device and session lineage. Both candidate datasets
have shared collection infrastructure within each release.
Neither establishes new-site or live-network performance on its
own. This milestone used publisher documentation only. Dataset
acquisition and model fitting remain for a separately approved step.

## What G13–G19 established

| Finding | Implication for v2 |
| --- | --- |
| G13 reserved the NF-CSE-CIC-IDS2018 benchmark and proposed a portable flow contract. | Keep the benchmark sealed while selecting data, features, models and thresholds. Validate semantics before adding another exporter. |
| G14–G15 found 67.32% of NF-ToN-IoT-v2 rows in conflicting six-feature groups. Adding IP packet-length extrema and TCP flags reduced that to 64.82%. | Enriching behavior features can reduce ambiguity. A richer vector still cannot recover capture provenance or resolve unreliable labels. Do not use IPs or ports to make the ambiguity disappear. |
| G16's combined tuple/vector grouping failed the prespecified balance criteria on its 250,000-row sample. G17 could not establish a reliable mapping from NF-ToN-IoT-v2 rows to the original TON_IoT capture or event windows. | Obtain original capture-linked data. Exported tuples are diagnostic keys and cannot stand in for proven original sessions. |
| G18 found nonfinite rates, negative header lengths and 9.99% of corrected CIC-IDS2017 rows in conflicting six-feature groups. G19 obtained zero audited key overlap, but Friday retained only 26.59% of its attacks and 0.68% of its Portscan rows. | Keep suspect fields out of the feature contract. Use whole original captures and independently verify copied rows and sessions. Make ordinary repeated behavior a diagnostic, and measure the selection bias of any novelty filter. Do not rerun the G19 split with relaxed gates. |

[G13 data strategy](LEVEL_2_DATA_STRATEGY.md) · [G14 audit](LEVEL_2_DATA_AUDIT.md) · [G15 feature study](LEVEL_2_FEATURE_ENGINEERING.md) · [G16 pilot](LEVEL_2_EXPERIMENTAL_BASELINE.md) · [G17 provenance](LEVEL_2_PROVENANCE_AND_DATA.md) · [G18 audit](LEVEL_2_CIC_AUDIT.md) · [G19 chronological validation](LEVEL_2_CHRONOLOGICAL_BASELINE.md)

## Source and label coverage

### IoT-23 v2

- **Captures and clock.** The CTU Stratosphere lab lists 20 malware
  captures and eight benign files from 2018–2019. The malicious
  captures used Raspberry Pis, while benign recordings came from
  Philips Hue (`4-1`), Amazon Echo (`5-1`), and Somfy
  (`7-1` through `7-6`). The v2 index gives dates, durations,
  device types and capture-specific metadata. The log contract
  uses Zeek `ts` for the first observed packet, in Unix seconds,
  and `uid` for a connection within an export. Scope a UID by
  source capture and export run. Check epoch bounds against
  publisher metadata and keep any rotated pieces of an original
  run together. Neither a UID nor a reused private IP establishes
  physical device identity across runs.
  [Publisher v2 summary and changelog](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/README.html) · [Zeek connection fields](https://docs.zeek.org/en/current/scripts/base/protocols/conn/main.zeek.html#type-Conn::Info) · [Zeek log formats](https://docs.zeek.org/en/current/log-formats.html)
- **Labels.** The publisher describes analyst-created, per-capture
  rules applied to Zeek data. The original release documents a
  binary label and a detailed behavior label. Examples include scanning, C&C,
  DDoS and file download, alongside malware-family names and
  compound tags. Family and capture names describe the run. They
  cannot label individual connections. Accept explicit
  `Benign` and `Malicious` after validating the exact v2 header,
  rule defaults, and scope. Keep unrecognized, unresolved or
  missing binary labels outside the supervised cohort. A missing
  detailed category alone does not invalidate an otherwise
  verified binary label. Record explicit negatives from known
  benign runs separately from lower-confidence negatives in
  malware runs. Keep raw composite labels and publish any
  nonexclusive category mapping. The v2 summary lists run-level
  families, but eligible per-flow class and category counts
  require an audit. V1 counts cannot establish v2 support.
  [Original behavior label definitions](https://www.stratosphereips.org/datasets-iot23) · [V2 labeling notes](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/README.html) · [Publisher's rule-based labeler](https://github.com/stratosphereips/netflowlabeler)
- **Formats, size and terms.** V2 provides per-capture Zeek text
  logs, `labels.config`, READMEs and PCAPs. The listed
  `zeek-labeled/` directory can also contain an ordinary
  `conn.log` alongside a separately published labeled export.
  Pin the intended artifact and treat different exports of a
  recording as one group. No separate standardized NetFlow or
  CSV artifact was verified for v2. The publisher's older
  archives are **8.7 GB flow-only** and **20 GB full** as
  advertised for v1. V2 has individual PCAPs up to about 21 GB.
  Listed labeled logs range from kilobytes to gigabytes.
  A consolidated v2 flow-only size was unverified. Plan
  against the exact v2 file list. The original dataset README
  states CC BY. The v2 index does not state a separate license,
  and some legacy scenario READMEs contain an authorization
  notice. Confirm terms for the exact selected v2 flow files
  before acquisition and redistribution.
  [Original release and terms](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/) · [Legacy scenario notice](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-IoT-Malware-Capture-34-1/) · [Example v2 labeled file](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/CTU-IoT-Malware-Capture-3-1/) · [Nested log listing](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/CTU-IoT-Malware-Capture-3-1/zeek-labeled/)

The main threat to validity is recognizing the collection setup.
The infected and benign device types differ, so flows can encode
device behavior even after dropping explicit IDs. Label rules can
also use observable flow behavior. Audit what the exact rule files
use before admitting features such as byte count or periodicity.
Report results separately for explicitly benign runs and reviewed
normal flows on the same platform as malicious runs, if available.
The split measures transfer to other recorded runs in this lab.

### CTU-13

- **Captures and clock.** CTU recorded thirteen numbered botnet
  scenarios in 2011 involving university background traffic,
  controlled normal traffic and botnet traffic. Use the publisher's
  recommended bidirectional Argus exports. Retain capture and
  export identity, recorded absolute start time and duration.
  Verify timezone, timestamp precision and epoch conversion for
  the actual files before comparing time windows. The scenario-2
  README records an August 2011 start in CEST. One scenario
  lasted almost 67 hours. Check full intervals on the shared
  university link. The published text contract has a five-tuple
  and direction fields. A stable
  cross-capture session ID was not verified. Group known repeated
  devices, malware samples, and capture fragments when supported.
  [Release and capture metadata](https://www.stratosphereips.org/datasets-ctu13/) · [Scenario-2 clock](https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-43/README.html) · [Authors' methods paper](https://doi.org/10.1016/j.cose.2014.05.011) · [Argus format reference](https://qosient.com/argus/man/man1/ra.1.pdf)
- **Labels and scope.** The authors distinguish `Normal`,
  `Botnet`, `Background` and a published C&C column. The
  historical paper describes host-based labeling. A flow
  involving a known infected host does not prove malicious
  behavior at the flow level. Use verified explicit Normal as
  the negative label and explicitly assigned Botnet flows for
  the source-native target. A scenario README documents
  `From-Botnet` labels. Verify actual strings and label rules
  per export. Inspect C&C semantics and counting
  before including that class in a binary mapping. Keep unknown
  and Background outside the supervised cohort. Table 4 sums
  to 20,643,076 flows across the 13 scenarios, including
  369,806 Normal, 432,755 Botnet, 11,111 in the C&C column and
  19,829,404 Background. The paper's earlier extraction has
  different totals. Background makes up about 96% in Table 4,
  so performance on eligible rows applies to a small part of
  the capture. C&C, scanning, spam and DDoS are documented for
  different scenarios. Treat scenario behaviors as cohort
  descriptions unless row labels supply that category.
  [Publisher scenario behaviors](https://www.stratosphereips.org/datasets-ctu13/) · [Publisher Table 4](https://images.squarespace-cdn.com/content/v1/5a01100f692ebe0459a1859f/1510069535476-AO1EJKKV3EAZLRDOV8ZC/Table4.jpg) · [Authors' labeling and collection methods](https://ri.conicet.gov.ar/bitstream/11336/6772/2/CONICET_Digital_Nro.9220_A.pdf)
- **Formats, size and terms.** The catalog advertises about
  **1.9 GB** for the combined archive. Per-capture bidirectional
  `.biargus` and Argus text `.binetflow` are the relevant
  formats. A complete text pass at an assumed 150–250 bytes
  per row would use roughly 3–5 GB before scratch storage.
  Treat this as a planning estimate and measure selected files
  first. Ordinary NetFlow CSV and Zeek connection logs have
  different semantics. The authors do not provide the complete
  mixed PCAP for privacy reasons. Botnet-only packet captures
  cannot recreate the full labeled normal and background
  cohort. Use flow-only downloads if authorized. The catalog
  requests citation. A reuse license for the specific CTU-13
  flow files was not verified. Confirm terms before acquiring
  them. Host labels, private addresses, ports, Type of Service,
  traffic direction and run-specific Argus settings can reveal
  capture roles. Keep identifiers and unverified settings out
  of predictors.
  [CTU-13 distribution](https://www.stratosphereips.org/datasets-ctu13/) · [Publisher Argus and text-export FAQ](https://www.stratosphereips.org/datasets-faq)

### Alternatives and transfer data

| Source | Role and limitation |
| --- | --- |
| UNSW-IoTraffic | Candidate for an independent-environment negative traffic audit. The authors report 27 device-specific traces, about 203 days and 4.94 million flows. Dryad lists a 95.51 MB flow-only ZIP. Five-tuples, UTC timestamps, per-device sequence numbers and direction are documented. Its byte fields are payload totals, and the authors provide no event or interaction ground truth. Treat its flows as unlabeled until an approved subset has independently supported negative labels. It can never supply attack recall on its own. [UNSW release](https://iotanalytics.unsw.edu.au/unsw-iotraffic.html) · [Dryad field definitions and files](https://doi.org/10.5061/dryad.w0vt4b94b) |
| CIC IoT-DIAD 2024 | Candidate for broader device and attack coverage at a different institution. UNB publishes native CICFlowMeter flow CSVs and packet-feature CSVs and describes 33 attack scenarios in seven categories, with benign traffic also listed. Require original capture, run and device lineage, byte semantics and mixed class support before selecting it. Count devices and verified capture groups separately. Verify lineage before treating it and CICIoT2023 as distinct collections. The download footprint and terms for a suitable subset remain to be confirmed. [UNB dataset and schema](https://www.unb.ca/cic/datasets/iot-diad-2024.html) |
| Authorized isolated lab and independently sourced recordings | Collect separate benign sessions from multiple devices and workloads with a pinned exporter, run IDs, timestamp bounds and documented observation points. For mixed evaluations, use approved prerecorded, independently labeled traffic or synthetic fixtures offline. Preserve source capture and event lineage, mark unresolved intervals unknown, and keep each original recording together. Hold out a whole environment recorded independently. A sandbox fixture or benign-only collection measures limited behavior, and a same-lab split remains a controlled evaluation. |

## Feature compatibility

`flow-core-v1` is the existing nProbe contract with transport
protocol, integer duration in milliseconds and directional packet
and IP-octet counters. Preserve this adapter. Qualify a separate
Zeek-native contract for the first IoT experiment and version it
before training. A common feature name or unit does not establish
parity. Verify how the collector chooses direction, closes flows,
handles retransmissions and truncation, and represents missing
counters.
[Existing adapter](../ml/level2_flow_schema.py) · [G17 counter semantics](LEVEL_2_PROVENANCE_AND_DATA.md) · [Zeek field definitions](https://docs.zeek.org/en/current/scripts/base/protocols/conn/main.zeek.html#type-Conn::Info)

| Feature | IoT-23 Zeek export | CTU-13 Argus export and transfer decision |
| --- | --- | --- |
| Transport protocol | Map known `proto` tokens to a documented taxonomy. Keep missing or unsupported values explicit. Check ICMP and IPv6 handling before claiming numeric equivalence. | Validate `Proto` names against the export. Compare only shared verified categories. |
| Duration | `duration` in seconds is optional. Zeek can omit trailing TCP packets from its duration. Preserve precision in the native schema and fix the rounding policy before any millisecond conversion. | `Dur` represents an Argus transaction duration. Verify time units and aggregation for the artifact. Similar units do not imply the same flow boundaries. |
| Directional packets | `orig_pkts` and `resp_pkts` track observed packets with the size analyzer enabled. Originator and responder follow Zeek connection semantics. | Text commonly gives `TotPkts`. A directional split requires corresponding `spkts` and `dpkts` in a verified Argus artifact. A total cannot reconstruct both directions. |
| Directional bytes | Use optional `orig_ip_bytes` and `resp_ip_bytes` for IP octets. Zeek's `orig_bytes` and `resp_bytes` are different payload counters. | Text totals and source bytes may permit a reverse count after verifying same accounting and direction. Verify the measurement layer. Keep Argus native until tested against equivalent exports. |
| Timing, flags and protocols | Test connection state, directional response behavior and rates only after the label-rule audit. Zeek `history` summarizes events and is not an exact TCP flag mask or numerical retransmission counter. Header-level IAT, size extrema, TTL and exact flags require instrumented extraction. | `State` and `Dir` are exporter-specific. Do not merge them with Zeek state or history. Protocol or service features require the same detector logic and evidence they generalize. |

Begin with protocol, duration, and directional packet and IP-byte
counts on one verified Zeek export contract. Compare a
no-byte variant where byte-based labeling or capture fingerprints
are suspected. Define zero-duration rate behavior, casting and
missing policies before fitting. Preserve unset fields separately
from measured zeros and report eligibility by class and capture.
No ports, IPs, MACs, UIDs, time of day, absolute timestamps, site,
device identifiers, names, rule outputs, or labels enter the primary
matrix. Keep timestamps and endpoint keys locally for audit.
For future Rust ingestion, require matched-fixture parity on
one-way packets, midstream TCP, timeouts, reconnects, direction,
IPv6 and counter accounting before mapping a new collector.
[Argus field reference](https://qosient.com/argus/man/man1/ra.1.pdf) · [Zeek connection handling](https://docs.zeek.org/en/current/advanced/devel/conn.html)

## Proposed development partitions

The following IoT-23 v2 capture assignments are proposals for an
audit. The IDs are suffixes of the publisher's
`CTU-IoT-Malware-Capture` and `CTU-Honeypot-Capture` names.
The schedule does not establish original-session or hardware
independence. If shared physical devices, related sessions or
duplicate recording material connect proposed roles, revise the
manifest as a whole before fitting or stop the experiment.

| Role | Malware-run candidates | Benign evidence to qualify | Allowed use |
| --- | --- | --- | --- |
| Fit | `1-1` (Hide and Seek), `3-1` (Muhstik) | Hue `4-1` plus reviewed normal flows in fit runs | Fit feature transforms, class weights and model parameters. |
| Probability and threshold calibration | `8-1` (Hakai) | Echo `5-1` plus reviewed normal flows in the same role | Use disjoint capture subsets inside this role for a probability mapping and cutoff selection. With too few groups, skip the probability mapping and select a cutoff from raw scores here. |
| Model comparison | `20-1` and `21-1` (Torii, kept together as a family) | Independently verified negatives in these runs or an additional approved benign capture with compatible collection and labeling | Compare fixed candidates at the calibration cutoffs. Do not move thresholds based on these scores. |
| Locked development validation | `34-1` (Mirai), `42-1` (Trojan) | Somfy `7-1` through `7-6` as one recording group plus verified normal flows in validation runs | Score the selected and frozen pipeline once. Only aggregate data-quality and class-support checks precede the lock. |

[Publisher capture table](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/README.html) · [Torii run 20-1](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/CTU-IoT-Malware-Capture-20-1/) · [Torii run 21-1](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/CTU-IoT-Malware-Capture-21-1/README.html)

This design tests separate named runs, including held-out family
names relative to the fit set. It cannot guarantee coverage of
unseen behavior types or independent sites. The two Torii runs
may be one analysis group for family-level inference. Some run
metadata reuse a private host or gateway address across roles.
Review original device inventory and collection notes. If no
verified negatives remain for comparison, add a separately
approved source with matched collection conditions or defer the
experiment. The small Hue, Echo, and later Somfy log listings
do not establish the negative denominators. The proposed
calibration has only one malware run, so the initial pilot
would skip fitting a separate probability mapping. Never use
Somfy fragments to fill multiple roles.
Hold the entire Somfy group in validation even if the first
download covers only a metadata-selected subset of its shards.
Report the incomplete coverage explicitly.

**CTU-13 fallback.** The official Table 4 gives both classes in
all 13 scenarios. The proposed family-disjoint assignment below
uses the publisher's counts for Normal and Botnet only. The
counts are metadata estimates before artifact and eligibility
checks. They do not show how many independent devices, sessions,
or genuinely malicious actions remain. The final role stresses
just one family. This supports a source-native feasibility study
with a weak host-derived target. Do not pool these labels or
features with the primary Zeek experiment.

| Role | Scenarios and families | Published Normal | Published Botnet |
| --- | --- | ---: | ---: |
| Fit | 1, 2, 9 (Neris), 7 (Sogou) | 84,524 | 238,689 |
| Calibration | 5, 13 (Virut) | 36,618 | 39,486 |
| Model comparison | 6 (Menti), 8 (Murlo), 12 (NSIS.ay) | 87,944 | 11,626 |
| Locked development validation | 3, 4, 10, 11 (Rbot) | 160,720 | 142,954 |

[Publisher label counts](https://images.squarespace-cdn.com/content/v1/5a01100f692ebe0459a1859f/1510069535476-AO1EJKKV3EAZLRDOV8ZC/Table4.jpg) · [Authors' scenario and family tables](https://ri.conicet.gov.ar/bitstream/11336/6772/2/CONICET_Digital_Nro.9220_A.pdf)

### Feasibility gates before fitting

1. **Provenance.** Pin the publisher URL, release, exact artifact,
   bytes, SHA-256, original capture and parent group, observed
   clock bounds, sensor/exporter version and configuration where
   known, label rule hash, and terms. Separate scoped UID overlap
   from evidence of the same original recording. Require zero
   copied rows, shared originals, or known linked sessions across
   roles. Assign known fragments and linked device/run groups
   together. A failed device-lineage check prevents any
   device-independent claim. Site transfer requires a genuinely
   separate collection with mixed ground truth and schema parity.
2. **Eligibility and coverage.** Audit rows, missingness, malformed
   values, unknown labels and rule-derived labels by role, class,
   category, group and protocol. Require at least 1,000 eligible
   examples of each class in every pilot role, a reviewable
   negative cohort from that role's captures, and at least two
   distinct original positive capture runs in final validation.
   Report per-capture rates with their denominators, and mark
   a rate with fewer than 100 eligible rows of its class as
   exploratory. Reserve stronger claims about low FPR for a
   later cohort with at least 10,000 verified negatives, 1,000
   verified positives and at least three defensibly independent
   capture groups contributing each class. Counts alone cannot
   establish statistical power when flows are correlated.
3. **Overlap and coverage shift.** Report exact typed-vector and
   direction-independent five-tuple overlap, as distinct keys and
   affected rows by role and class, for each feature contract.
   Use timestamp windows, capture provenance and IDs to determine
   whether overlap is copied/session-linked traffic. Resolve
   unexplained overlap before fitting. Ordinary repeated vectors
   and reused tuples with distinct provenance remain in the
   primary cohort. Report an additional known-vector versus
   novel-vector sensitivity analysis. Any filter is label-blind
   and fixed before scores. Require at least half of each
   verifiably labeled source class and each category with at least
   100 source rows in each role after eligibility filtering.
   Publish retained and rejected counts, class prevalence, per-role
   category coverage, missingness and capture concentration.
4. **Feature and label integrity.** Trace units and extraction to
   documentation or fixture tests. Stop if a primary feature is
   missing on a cohort or directly encodes the label. Compare
   distribution shifts by role, class, protocol, device family
   and capture. Document new categories and exclusions before
   scoring and leave final development flows and labels out of
   learning and threshold selection. Inspect only prespecified
   preflight aggregates there. If any applicable pilot gate
   fails, publish the audit and revise the collection plan.
   Do not substitute a row split.

[Grouped evaluation guidance](https://scikit-learn.org/stable/modules/cross_validation.html#cross-validation-iterators-for-grouped-data) · [Authors' research on label provenance](https://arxiv.org/abs/2305.01337)

## Model development and metrics

- **First experiment.** Use a fixed seed of 42 and identical
  roles and test eligibility across models. Benchmark a majority
  classifier, regularized Logistic Regression, and a
  single-worker, 24-tree Random Forest with depth capped at 10,
  at most 256 leaves per tree, and at least 20 samples per leaf.
  Fit categorical encoding, numeric transforms, scaling and any
  class weighting in the fit role only. Compare fit-only class
  weighting with the unweighted baseline when support allows.
  Keep natural class frequencies in calibration, comparison and
  validation. Freeze one common eligible row set for feature
  comparisons and report alternate-contract coverage separately.
- **Later candidates.** Give XGBoost and LightGBM small,
  fixed tree budgets and the same roles, predictors, scoring
  cohorts and compute reporting as Random Forest. Only add a
  small PyTorch model if enough independent groups and meaningful
  learning-curve evidence warrant the cost. Sequence inputs would
  require a separate scope, past-only features, and independently
  grouped sessions. Advance a more complex model only for a
  reproducible benefit at comparable recall and false-positive
  rates and reasonable inference cost.
- **Calibration and cutoff.** Report the 0.5 default. On
  threshold-calibration captures, maximize macro attack recall
  subject to pooled FPR budgets of 5% and 1%. Decline any
  operating point that cannot also attain the 95% recall
  objective there. Break equal-recall ties by lower pooled FPR,
  then by higher threshold. A cutoff issuing no alerts is
  infeasible under the recall constraint. When a separate
  probability-calibration capture set qualifies, fit a sigmoid
  mapping using only its held-out scores. Compare reliability
  curves, Brier score and log loss where denominators permit.
  Freeze the mapping and cutoff before model comparison. Compare
  candidates at the same operating budget and report observed
  rates together. Any new threshold, feature, or model choice
  after opening final development scores requires a fresh holdout.
- **Reporting.** Publish confusion matrices (TN, FP, FN, TP),
  accuracy, balanced accuracy, precision, recall, F1, FPR,
  ROC AUC and average precision, plus ROC and precision-recall
  curves. Include per-capture rates, micro totals, macro
  averages and the worst supported capture, with coverage and
  attack-category recall under the same threshold. Mark rates
  with absent denominators as unavailable. Use uncertainty by
  resampling independent capture groups where enough exist.
  With too few groups, publish counts and ranges and qualify
  uncertainty. Record fit time, peak memory, inference
  throughput and latency at fixed batch sizes, model size,
  hardware, dependency versions and seed. For SOC evaluation,
  also report false alarms per monitored time and alert workload
  where the collection has a meaningful exposure denominator.

[Probability calibration reference](https://scikit-learn.org/stable/modules/calibration.html) · [Decision threshold reference](https://scikit-learn.org/stable/modules/classification_threshold.html)

The G20 research objectives are **accuracy ≥95%, recall ≥95%
(stretch ≥99%), FPR ≤5% (stretch ≤1%), precision ≥95%** and
strong balanced accuracy and F1 on independent captures.
Treat the numbers as aspirations. Recall and FPR must be
evaluated jointly. Precision also depends on prevalence. With
1% attack prevalence, a hypothetical detector with 95% recall
and 1% FPR would reach about 49% precision. Report observed
prevalence and separately label any illustrative workload
calculation. Compare model performance only on a common task
and eligibility basis.

## Bounded G21 proposal

1. **Preflight and request acquisition approval.** Recheck the
   v2 release and terms for the exact named logs, pin length
   and capture lineage, and present a manifest for approval.
   The publisher lists about 138 MB and 23 MB for the two
   proposed fit logs and about 2.9 MB for `34-1`. The
   Somfy `7-1` flow log alone is listed at about 1.2 GB.
   Start with labeled logs, READMEs, and label-rule metadata
   only, using the smaller Somfy shards if their sizes and
   provenance check out. Keep the large shard assigned to the
   same role for any later approved expansion. Put any approved
   downloads in ignored `data/level2/iot23-v2/` on D:.
   Recheck the file listings because the direct publisher
   host timed out during parts of the G20 metadata review.
   Cap the first batch at **512 MiB total transfer** and plan
   **5 GiB** free for raw input, scratch indexes and aggregates.
   These are local limits. Measure actual lengths, enforce the
   cap while streaming, and request approval for expansion if
   required. No full archives, PCAPs, or malware executables are
   part of this plan.
   [Fit file 1-1](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/CTU-IoT-Malware-Capture-1-1/) · [Fit file 3-1](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/CTU-IoT-Malware-Capture-3-1/) · [Mirai file 34-1](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/CTU-IoT-Malware-Capture-34-1/) · [Somfy file 7-1](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/CTU-Honeypot-Capture-7-1/)
2. **Build and audit a native adapter.** Validate header,
   label mapping, number types, missing values and timestamps
   with synthetic fixtures. Stream in chunks of up to 50,000
   rows and reuse disk-backed grouping to audit the acquired
   files. Save source hashes, roles, coverage, category
   counts, overlap decisions and gate status. Produce a
   machine-readable manifest without raw endpoints or labels
   in Git. Measure scratch and memory in a metadata-to-cohort
   smoke run. If official files cannot be pinned or the
   required negatives cannot be verified, stop at the audit.
3. **Run bounded baselines only if the approved gates pass.**
   Start with a synthetic smoke test and a deterministic,
   group-complete sample capped at 120,000 fit rows. Preserve
   all roles and avoid taking the first rows of a time-sorted
   capture or splitting a verified session to meet the cap.
   Run on CPU with one training worker. Measure resource usage
   and stream evaluation predictions if needed. Expand only
   after documenting what the initial cohort could and could
   not support. Additional datasets, exporters, algorithms
   and larger experiments follow a separate decision.

The Level 1 application, frozen Random Forest and official
evaluation stay intact. The NF-CSE-CIC-IDS2018 benchmark and
derivatives remain sealed through development. Promotion
requires a frozen evaluation protocol and credible evidence on
independent captures. G20 changes documentation only.
