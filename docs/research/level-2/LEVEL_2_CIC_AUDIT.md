# G18 · Corrected CIC-IDS2017 acquisition and native-schema audit

## Scope and provenance

G13 reserved the 2018 evaluation campaign. G14 and G15 documented
weak provenance and extensive exact-vector ambiguity in NF-ToN-IoT-v2.
G16 found that keeping identical predictors and exported tuples together
failed the prespecified split balance criteria on its samples. G17
recommended the CNS 2022 corrected 2017 release as a different
development campaign. LYCOS is a separate export of the same 2017
traffic and remains outside this audit.
[G13 strategy](LEVEL_2_DATA_STRATEGY.md) · [G14 audit](LEVEL_2_DATA_AUDIT.md) · [G15 feature analysis](LEVEL_2_FEATURE_ENGINEERING.md) · [G16 pilot](LEVEL_2_EXPERIMENTAL_BASELINE.md) · [G17 provenance](LEVEL_2_PROVENANCE_AND_DATA.md)

After explicit approval, the official `CICIDS2017_improved.zip`
was downloaded onto D: under `data/level2/cicids2017-improved/`.
Its **343,549,013 bytes** matched the publisher's HTTP length.
Its local SHA-256 is
`97fdb91d339e2d8cf5627f981b831e5e7e400b981c58181c451a38fd03c48883`.
A separate publisher-authenticated checksum was unverified. The audit
reads CSVs directly from the ZIP and verifies their CRCs as it consumes
them. The archive contains exactly five daily CSVs, with no bundled
readme or metadata manifest. The published CIC documentation and the
correction authors' notes provide the capture lineage and labeling
method. UNB provides the data for research with citation. These files
stay local under the research-use assumptions identified in G17.
[Author archive listing](https://intrusion-detection.distrinet-research.be/CNS2022/Datasets/) · [Correction paper](https://doi.org/10.1109/CNS56114.2022.9947235) · [Correction notes](https://intrusion-detection.distrinet-research.be/CNS2022/CICIDS2017.html) · [UNB release](https://www.unb.ca/cic/datasets/ids-2017.html) · [Original dataset paper](https://doi.org/10.5220/0006639801080116)

## Audit method

The native headers and CSV records remain intact. The runner counts raw
labels and the literal `Attempted Category` values. Its analytical binary
policy treats `BENIGN` and entries marked attempted by the published
marker as benign, following the authors' recommendation. That policy is
explicit in the report and writes no rows back to the archive. An
experiment should preregister a separate attempted-label sensitivity
analysis rather than silently changing labels.
[Author label guidance](https://intrusion-detection.distrinet-research.be/CNS2022/Dataset_Download.html)

The program counts blanks, numeric types, nonfinite and malformed
values, zero and negative counts, and numeric ranges for each column
and daily CSV. It reads up to 4,096 rows at a time. It uses bounded
disk-backed exact grouping for decoded full records excluding the
exported `id`, native six-field vectors, bidirectional endpoint
tuples, and exported flow IDs. Each group records repeats and class
support. The overlap audit counts affected rows separately on each
side of a proposed boundary. It checks timestamp parsing, day
membership, file-order backsteps and duration-derived clock spans.
The JSON contains aggregates and headers, with no raw flows or endpoint
values. [Audit runner](../../../ml/audit_cic_release.py) · [Exact grouping](../../../ml/level2_audit_storage.py)

## Full audit results

All five CSVs passed their ZIP CRC checks. They share one 91-column
header and total 1,152,270,765 uncompressed bytes. The Windows audit
finished in about 7 minutes and 42 seconds. Under the declared binary
policy, 1,594,545 records are benign (75.93%) and 505,431 are attacks
(24.07%).

| CSV | Capture date | Records | Benign | Attack | CRC32 |
| --- | --- | ---: | ---: | ---: | --- |
| `monday.csv` | 2017-07-03 | 371,624 | 371,624 | 0 | `e08d4445` |
| `tuesday.csv` | 2017-07-04 | 322,078 | 315,145 | 6,933 | `df090cf7` |
| `wednesday.csv` | 2017-07-05 | 496,641 | 324,996 | 171,645 | `f5b1c8f4` |
| `thursday.csv` | 2017-07-06 | 362,076 | 290,169 | 71,907 | `fe95440c` |
| `friday.csv` | 2017-07-07 | 547,557 | 292,611 | 254,946 | `2acdecd2` |
| **Total** | | **2,099,976** | **1,594,545** | **505,431** | |

### Label coverage

| Capture day | Attack labels and support under the binary policy | Attempted rows counted as benign |
| --- | --- | ---: |
| Monday | None | 0 |
| Tuesday | FTP-Patator 3,972, SSH-Patator 2,961 | 39 |
| Wednesday | DoS Hulk 158,468, DoS GoldenEye 7,567, DoS Slowloris 3,859, DoS Slowhttptest 1,740, Heartbleed 11 | 5,876 |
| Thursday | Infiltration - Portscan 71,767, Web Attack - Brute Force 73, Infiltration 36, Web Attack - XSS 18, Web Attack - SQL Injection 13 | 1,997 |
| Friday | Portscan 159,066, DDoS 95,144, Botnet 736 | 4,067 |

There are 1,582,566 literal `BENIGN` records and 11,979 attempted
records. The release contains 27 raw label spellings including
`BENIGN` and the attempted variants. Wednesday's attack class is
dominated by Hulk, and almost all Thursday attacks are Infiltration -
Portscan. Every Thursday and Friday attack label is absent from
Tuesday–Wednesday under its exact published name. Friday attack
labels are also absent from Thursday. Report per-category
denominators alongside pooled scores.

### Value quality and clock checks

- Of 91 columns, 60 are integer-valued and 25 contain decimal values,
  including two rate columns with nonfinite entries. The other six
  are textual fields or semantic metadata. These are `Flow ID`,
  `Src IP`, `Dst IP`, `Timestamp`, `Label`, and `Attempted Category`.
  The audit found zero blank fields, malformed numeric entries, or
  rejected records for the six-field native contract.
- There are five zero-duration flows and five nonfinite entries each
  in `Flow Bytes/s` and `Flow Packets/s`. There are negative values
  in 309 forward and 472 reverse header-length entries. Their cause
  remains unverified. Each ICMP metadata field contains 2,099,373
  occurrences of `-1`. Keep the rate, header-length, and ICMP fields
  out of the initial predictor contract. The grouped audit also
  recorded 33 zero forward-packet counts and 1,510 protocol-zero
  values. Treat their exporter semantics as a portability check
  before accepting such inputs from another collector.
- All timestamps parsed and belonged to their member's capture date.
  They have microsecond precision and no timezone offset. The authors'
  labeling code compares the timestamps against epoch-derived event
  windows. This audit uses the exported clock without a timezone
  conversion. First starts fall between 11:42 and 11:59, and the last
  duration-derived end on each day falls between 20:00 and 20:11.
  No computed end crossed its start date. There were 937,776
  adjacent file-order timestamp backsteps, so row order is unsuitable
  as a chronological boundary.
  [Author labeling notebook](https://github.com/GintsEngelen/CNS2022_Code/blob/main/Labelling/CICIDS2017_labelling_fixed_CICFlowMeter.ipynb)
- The `id` value equals the one-based row number in each file.
  The exported `Flow ID` exactly matches the source-oriented
  five-tuple serialization for 2,098,132 rows. Use endpoint keys as
  scoped grouping diagnostics and treat capture IDs, row position,
  ports, and topology as possible campaign shortcuts.

### Duplicates and group overlap

Repeat occurrences count every row after the first within a group.
Repeated-group rows and conflicting-group rows include all members.
Conflict means at least one attack and one benign row under the
declared policy. Tuple and flow-ID conflicts describe repeated
identifiers, which can legitimately carry different traffic.

| Key | Distinct groups | Repeat occurrences | Rows in repeated groups | Conflicting groups / rows | Cross-day groups / rows |
| --- | ---: | ---: | ---: | ---: | ---: |
| Full decoded record except `id` | 2,099,976 | 0 | 0 | 0 / 0 | 0 / 0 |
| Six typed native predictors | 1,569,131 | 530,845 | 600,388 | 255 / 209,817 | 53,782 / 516,020 |
| Direction-independent five-tuple | 1,084,249 | 1,015,727 | 1,245,812 | 7,101 / 106,993 | 147,827 / 1,006,320 |
| Exported `Flow ID` | 1,084,507 | 1,015,469 | 1,245,681 | 7,131 / 105,977 | 147,640 / 1,003,085 |

The full-record comparison includes timestamp and label. At the
predictor level, 28.59% of rows belong to repeated vectors and 9.99%
belong to conflicting vectors. The largest six-feature group contains
12,764 rows. A row-level random split can therefore repeat inputs
across partitions, and the six-feature model cannot distinguish
opposing labels within an identical vector.

## Native feature contract and leakage

The initial baseline contract is protocol number, microsecond flow
duration, forward/reverse packet counts, and forward/reverse transport
payload byte counts. The fixed exporter measures flow time from its
packet timestamps. Direction is the exporter's forward/reverse pairing.
Use G17's typed native adapter. It preserves orientation and precision.
The native byte totals cannot be used as `flow-core-v1` IP-layer bytes.
For future Zeek or Rust work, test timeout and termination semantics,
originator assignment, packet inclusion, sampling and byte accounting
using shared fixtures before any cross-export comparison. A Zeek
connection has both payload-byte and IP-layer counters with different
semantics. The initial contract also excludes derived rates and
topology-dependent fields. Consider selected native TCP count features
only as a subsequent documented ablation. A count is distinct from
the cumulative flag masks used in the nProbe experiments.
[CIC header definitions](https://github.com/GintsEngelen/CICFlowMeter/blob/master/src/main/java/cic/cs/unb/ca/jnetpcap/FlowFeature.java) · [CIC packet extraction](https://github.com/GintsEngelen/CICFlowMeter/blob/master/src/main/java/cic/cs/unb/ca/jnetpcap/PacketReader.java) · [CIC byte and duration code](https://github.com/GintsEngelen/CICFlowMeter/blob/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java) · [Zeek connection fields](https://docs.zeek.org/en/current/scripts/base/protocols/conn/main.zeek.html#type-Conn::Info) · [Native adapter](../../../ml/level2_provenance.py)

Keep `id`, `Flow ID`, addresses, ports, timestamps, capture day,
labels and attempted markers outside the predictor matrix. The source
labeling depended in part on host and time information. The capture
schedule and class support by day can let a model learn the testbed
instead of traffic behavior. Some corrected labels also depend on
forward payload length. Keep that label-construction dependence
visible when testing the native payload features, and run a
predeclared payload-free sensitivity check. Tuple and ID overlaps are grouping
diagnostics. Repetition does not by itself identify the same underlying
session. [Author correction notes](https://intrusion-detection.distrinet-research.be/CNS2022/CICIDS2017.html)

## Split feasibility and next experiment

The candidate boundary follows G17. Fit on Tuesday and Wednesday,
calibrate on Thursday, and reserve Friday for within-campaign
validation. Monday supports a separate benign FPR check. Both
calibration and validation days have substantial binary class counts
before any group exclusions. The measured start and end ranges also
support a chronological capture-day boundary within this campaign.
The raw day assignment fails group isolation.

| Boundary | Shared key | Shared groups | Later-side benign rows | Later-side attack rows |
| --- | --- | ---: | ---: | ---: |
| Tuesday–Wednesday → Thursday | Native vector | 20,523 | 52,868 | 16,794 |
| Tuesday–Wednesday → Thursday | Bidirectional tuple | 57,967 | 134,206 | 104 |
| Tuesday–Wednesday → Thursday | Exported flow ID | 57,945 | 134,184 | 102 |
| Tuesday–Thursday → Friday | Native vector | 24,881 | 62,390 | 157,127 |
| Tuesday–Thursday → Friday | Bidirectional tuple | 78,825 | 148,399 | 29,453 |
| Tuesday–Thursday → Friday | Exported flow ID | 78,621 | 148,214 | 29,040 |

In Friday's full block, 219,517 rows (40.09%) share native vectors
with earlier days, including 61.63% of its attack rows. Monday is
benign-only, but 158,157 of its rows share a bidirectional tuple
with Tuesday–Wednesday. Exact-vector, tuple, and flow-ID counts
are measured separately and can describe the same rows.

**Readiness decision.** Corrected CIC-IDS2017 is a viable candidate
for a native-schema, within-campaign development experiment after
split verification. The unfiltered day assignment is unsuitable
for an isolation-checked baseline. The CSVs carry clock and tuple
metadata. They supply no verified session identifiers or independent
test environments. Time-based or inferred session grouping requires
verified exporter timeouts and capture-boundary evidence. It can
supplement the day split and carries no cross-environment guarantee.

For G19, first build a local eligibility manifest. Declare any
whole-group exclusions before fitting, preserve temporal roles, and
measure the union of overlaps on exact vectors and evidenced sessions.
Use the bidirectional tuple as a conservative sensitivity check.
Publish the exact retained class and category counts and verify zero
overlap for the chosen grouping policy across every boundary. Test
each feature variant separately because a change in columns changes
exact-vector identity. Retain the original archive and labels. If
support collapses or session linkage remains unverified, restrict the
result to an explicitly exploratory within-campaign pilot or obtain
an independently documented development capture with a compatible
exporter.
[Capture preflight](../../../ml/level2_provenance.py) · [G15 split planner](../../../ml/level2_splits.py)

After a feasible split is demonstrated, start with a fixed-seed,
group-complete sample and a target cap of 120,000 fitting rows.
Record any exception needed for a large indivisible group before
running. Compare a majority sanity check, regularized Logistic
Regression, and a small single-worker Random Forest with the same
native columns and identical approved folds. One-hot encode protocol
and fit numeric scaling only on the fit partition for Logistic
Regression. Keep the initial 24-tree forest bounded to depth 10
and 256 leaves per tree, with a fixed seed and at least 20 rows per
leaf. Evaluate the default threshold and select optional 5% and
10% FPR operating points using calibration only. Report confusion
counts, precision, recall, FPR, ROC AUC, average precision, and
coverage by day and attack category. The G13 research target remains
at most 10% FPR with at least 95% attack recall. Any such result
would apply to its observed split. Cross-environment testing needs
separately sourced captures and a verified compatible exporter
contract. The reserved external evaluation campaign stayed sealed.

## Reproduce

```powershell
$release = 'data/level2/cicids2017-improved'
& .\.venv\Scripts\python.exe -B -m ml.audit_cic_release |
    Set-Content -Encoding utf8 "$release/g18-audit.json"
if ($LASTEXITCODE -ne 0) { throw 'Corrected CIC audit failed.' }
& .\.venv\Scripts\python.exe -B -m unittest discover -s tests
```

The archive, output, temporary runs, and credentials are ignored by
Git. The five new synthetic tests cover CRC failures, attempted-label
handling, numeric and clock quality, duplicate and overlap counts, and
archive membership. The complete Python suite passed all 131 tests.
The frontend suite passed all 22 tests and the production build
succeeded. Level 1 stayed frozen and G18 trained no models.
