# G15 · Feature engineering and validation design

## Scope

This milestone examines the pinned **NF-ToN-IoT-v2** development CSV
acquired in G14. It measures what happens when the same rows are mapped
to different predictor sets. A conflicting vector is an exact typed
predictor tuple with both benign and attack labels. These descriptive
measurements use the development labels. They provide no performance
estimate for future captures or a fitted model.
[G14 dataset audit](LEVEL_2_DATA_AUDIT.md) · [Level 2 data strategy](LEVEL_2_DATA_STRATEGY.md)

## Method and resource estimate

The first timing pilot compared all eight projections on the first
250,000 records. It took 33.13 seconds in the initial runner. A linear
extrapolation was about 37 minutes, with an **11.93 GB** unmerged
scratch envelope before merge overlap if every row produced a separate
key in every projection. The prefix is an I/O and CPU timing check.
Its composition depends on source order.

The two-projection pilot used 32 MiB per counter and completed the same
prefix in 3.94 seconds. Its linear extrapolation was about 4½ minutes.
The no-repeat scratch estimate was **2.74 GB** before compaction.
Later portions of the release can have higher key cardinality and more
merge work. That motivated comparing all eight on a distributed sample
and limiting the full exact run to the baseline and **packet lengths
plus TCP flags**. That combination adds semantics available in
packet-aware exporters without using raw ports or TTL as host or
topology proxies.

The comparison CLI checks the G14 CSV SHA-256. Its distributed row sample
draws 250,000 distinct row ordinals without replacement using seed 42,
then reads those rows in file order. It verifies the release's physical
row count. Candidate summaries in each run use the intersection of rows
accepted by every candidate. The report includes raw blank counts,
candidate rejections by first failing field, and protocol-specific
inapplicability. The external sort keeps full key bytes and label counts
in bounded temporary runs on D:. It aggregates identical vectors across
chunks and never changes or deduplicates the source records.
[Comparison runner](../../../ml/compare_level2_features.py) · [Exact aggregation](../../../ml/level2_audit_storage.py)

## Findings

### Distributed sample

The sample contained 89,871 benign and 160,129 attack records. All eight
projections accepted all 250,000 rows, with zero raw blanks in the
selected columns. The family names below add fields to the same six-field
core. “Repeated occurrences” counts rows past the first in each vector
group. “Rows in conflicting groups” counts all rows in groups containing both
classes. Partners outside the sample can make a vector appear
unambiguous here, so compare projections within this table.

| Additional features | Distinct vectors | Repeated occurrences | Conflicting vectors | Rows in conflicting groups |
| --- | ---: | ---: | ---: | ---: |
| None | 31,728 | 218,272 | 292 | 154,205 (61.68%) |
| Ports | 240,428 | 9,572 | 34 | 79 (0.03%) |
| TCP flags | 32,022 | 217,978 | 164 | 151,115 (60.45%) |
| IP packet length extrema | 31,740 | 218,260 | 291 | 154,200 (61.68%) |
| TTL extrema | 31,795 | 218,205 | 284 | 154,137 (61.65%) |
| TCP retransmissions | 32,336 | 217,664 | 292 | 154,205 (61.68%) |
| IP packet lengths and TCP flags | 32,031 | 217,969 | 164 | 151,114 (60.45%) |
| All five families | 240,450 | 9,550 | 27 | 57 (0.02%) |

The combined projection without ports reduced the sample conflict share
by 1.24 percentage points using unrounded counts. TCP flags drove almost
all of this reduction. Retransmission fields split some repeated vectors
without changing the number of rows in mixed-label groups. Raw ports
split the sample into almost as many vectors as rows. That sparsity and
the use of ports in source labeling make the drop in measured ambiguity
weak evidence of portable attack detection. Treat the port-containing
projections as diagnostic.

The 328 sample rows outside TCP and UDP had structurally null ports.
The 36,883 non-TCP rows had structurally null TCP masks and retransmission
counters. Every applicable candidate field passed its type and range
checks, including the order of packet-length and TTL extrema.

### Feature quality across the release

G14's full-column audit found zero raw blanks in these feature families.
The following observed ranges and zeros identify issues that a lexical
check alone cannot resolve.

| Family | Full-release observations |
| --- | --- |
| Ports | Both columns range from 0 to 65,535 across all raw rows. The source column reports 22,258 zeros and the destination column 24,326. Protocol gating keeps pseudo-ports outside the candidate vectors. |
| TCP flags | Full-flow and directional masks range from 0 to 223. The full-flow mask is zero in 2,513,428 raw rows. This total includes non-TCP records. |
| IP packet extrema | Minimum lengths range from 0 to 597 octets, with 6,269,786 zeros. Maximum lengths range from 28 to 65,535 octets. Verify how zero minima and large observed lengths arise before assuming sensor equivalence. |
| TTL | Both extrema range from 0 to 255. Each is zero in 10,889,627 rows (64.28%). Zero may reflect exporter behavior, and host or path differences may affect the observed values. |
| Retransmissions | Forward and reverse packet counters are zero in 16,677,610 and 16,627,026 raw rows respectively. Positive counts can depend on exporter state and the capture point. |

### Full comparison and cause of ambiguity

Both projections accepted all **16,940,496 rows**, with zero raw blanks
or validation failures in the selected fields. Every baseline group
statistic agreed with G14. The complete comparison took **276.23 seconds**
in Python 3.12.3, excluding the initial checksum read. The temporary
runs were removed after merging.

| Measure | Six-field core | Core with IP packet lengths and TCP flags |
| --- | ---: | ---: |
| Distinct vectors | 686,858 | 716,943 |
| Repeated occurrences beyond the first | 16,253,638 | 16,223,553 |
| All rows in repeated groups | 16,446,082 | 16,412,674 |
| Conflicting vectors | 7,401 | 5,022 |
| Rows in conflicting groups | 11,403,591 (67.32%) | 10,981,142 (64.82%) |
| Largest group | 3,589,712 | 3,588,704 |
| Sum of the smaller class count in each vector | 712,895 (4.21%) | 653,746 (3.86%) |

The last row counts the minimum number of disagreements possible when
every exact vector gets one deterministic label on these observed rows.
It uses the labels for the calculation and supplies no estimate of
classifier performance. Each TCP mask is structurally null for the
2,513,423 non-TCP rows in the expanded projection.

Of the core's 11,403,591 conflicting rows, **10,782,146 (94.55%)** had
zero elapsed milliseconds and **5,991,955 (52.54%)** contained a single
packet. These properties can overlap. The largest core vector alone
represents TCP protocol 6, zero milliseconds, one forward packet of
44 exported octets, and zero reverse packets and octets. It groups
**3,103,043 benign and 486,669 attack records**. The projection retains
the same brief flow totals for different underlying records. It discards
the endpoint and transport context used in the release's labeling. Most
of this ambiguity persists with packet length extrema and flags. The
full comparison reduced the share in conflicting groups by 2.49
percentage points using unrounded counts.

These counts explain where the information is lost. They leave open
whether individual original labels were correct and whether the
additional measurements will transfer to another capture.

## Feature definitions and portability

The exporter orientation in each source field is part of the contract.
The feature adapter selects only explicitly allowed fields, validates
nonnegative integers against the project bounds, and checks that
reported minima do not exceed maxima. It preserves measured zeros.
A port is structurally inapplicable outside TCP and UDP. TCP flags and
retransmission fields are inapplicable outside TCP. Those nulls have
their own encoding and remain distinct from raw blanks and measured
zeros. No scaler, imputation, encoder, or classifier was fitted.
[Feature selection code](../../../ml/level2_feature_sets.py)

| Family | Fields and interpretation | Zeek and Rust feasibility |
| --- | --- | --- |
| Six-field core | IP protocol number, exporter duration in milliseconds, directional packet counts and directional exported octets. nProbe IN is source-to-destination, OUT is reverse. G14 measured forward octet values as low as 4 with a packet count above zero, so actual IP-layer byte parity remains open. | Zeek exposes the IP protocol, IP byte and packet counters when enabled, and connection duration in seconds. Tail-packet treatment, flow timeout, direction and rounding need matched fixtures. A Rust adapter can read equivalent flow exports after those semantics are verified. |
| Ports | `L4_SRC_PORT`, `L4_DST_PORT`. Unsigned 16-bit source and destination transport port IDs for TCP or UDP. The IDs are categorical if later used in a model. | Zeek exposes originator and responder ports. ICMP's pseudo-ports represent type and code and are excluded here. Rust can map verified TCP/UDP endpoint fields. Raw ports can encode service assignments and testbed roles. |
| TCP flags | `TCP_FLAGS`, `CLIENT_TCP_FLAGS`, `SERVER_TCP_FLAGS`. Exported cumulative bit masks for the full flow and exporter-defined client and server sides. The adapter preserves each mask separately. | Zeek's default `conn.log` history is a lossy event sequence. Exact masks require a packet-aware exporter or instrumented analysis with matching orientation and bit definitions. Rust could accumulate the same flags if supplied with defined packet-level data. |
| IP packet lengths | `MIN_IP_PKT_LEN`, `MAX_IP_PKT_LEN`. Whole-flow extrema of total IP packet lengths in octets, with IP headers included. The comparison avoids the exporter's separate shortest/longest fields. | Plain `conn.log` has directional totals. Exact extrema require packet header instrumentation or an exporter that supplies equivalent fields. Rust can ingest or aggregate them with validated header units, fragmentation rules, and flow boundaries. |
| TTL | `MIN_TTL`, `MAX_TTL`. Exported whole-flow minimum and maximum TTL, in the 0–255 integer range. Values depend on the sensor's position and the path. The interpretation of reported zero still needs exporter evidence. | Available from packet headers or a suitable exporter. Standard Zeek connection summaries omit these extrema. Validate IPv4 TTL and IPv6 Hop Limit handling before accepting another exporter. |
| TCP retransmission | `RETRANSMITTED_IN_PKTS`, `RETRANSMITTED_OUT_PKTS` and corresponding byte counts. Directional TCP retransmission counts in packets and exported octets. | Zeek history's retransmission markers are logarithmic. Exact per-flow counts require a compatible retransmission policy, byte basis, and flow boundary. Rust would need matching counters from an exporter or connection state with sequence tracking. |

These are field definitions and feasible extraction routes. A Zeek or
Rust mapping still needs parity fixtures on approved traffic with the
same observation point, sampling, timeouts, and direction assignment.
[nProbe flow fields](https://www.ntop.org/guides/nprobe/flow_information_elements.html) · [IANA IPFIX registry](https://www.iana.org/assignments/ipfix/ipfix.xhtml) · [Zeek connection fields and history](https://docs.zeek.org/en/current/scripts/base/protocols/conn/main.zeek.html#type-Conn::Info) · [Zeek packet event](https://docs.zeek.org/en/current/scripts/base/bif/event.bif.zeek.html#id-new_packet) · [Zeek TCP events](https://docs.zeek.org/en/current/scripts/base/bif/plugins/Zeek_TCP.events.bif.zeek.html#id-tcp_rexmit)

## Leakage and development split

The predictors exclude `Label`, `Attack`, IP addresses, data source
IDs, capture identifiers, row numbers, absolute timestamps, and session
IDs. Attack labels are used to count disagreements. The publisher assigned
labels by matching exported flows against source attack events using
addresses, ports, and protocol. This makes raw endpoints especially risky
predictors. Raw ports were included only in diagnostic projections.
TTL and exporter-specific counters can also encode testbed identity.
[UQ labeling method](https://arxiv.org/html/2101.11315#S3.SS2)

The v2 header has no absolute timestamp, capture ID, or session ID.
The parent UNSW release lists timestamped events, packet captures,
and Zeek exports. UQ regenerated flow boundaries with nProbe. Neither
source documents a row-level crosswalk from the delivered v2 rows to
capture files or recorded sessions. A five-tuple can recur across
different sessions and the v2 duration fields supply only elapsed
intervals. File order supplies no verified chronology.
[Parent ToN-IoT release](https://research.unsw.edu.au/projects/toniot-datasets) · [UQ extraction method](https://arxiv.org/html/2101.11315#S3.SS2)

### Exact-vector diagnostic

The distributed sample used three hash folds on the packet-length-plus-flags
vectors with seed 42. A fixed encoding and hash put every identical vector
in the same fold. The folds were strongly imbalanced even though all
included both classes.

| Fold | Benign | Attack | Total |
| --- | ---: | ---: | ---: |
| 1 | 30,555 | 48,298 | 78,853 |
| 2 | 51,728 | 51,285 | 103,013 |
| 3 | 7,588 | 60,546 | 68,134 |

Capture and session overlap are unknown. For a separate overlap check,
the audit grouped raw exported endpoint spellings in both directions,
retaining ports only for TCP/UDP five-tuples. It found **977 of 2,044** address pairs
in more than one fold, covering **245,082 rows**. It also found
**7,367 of 236,810** bidirectional TCP/UDP five-tuples in more than
one fold, covering **16,601 of 249,672** transport rows. These are
proxies for potential dependence. They can recur at different times
and do not identify a unique session or capture. The output contains
counts only. The address and tuple values were kept off the predictor
list and out of the report. [Diagnostic code](../../../ml/compare_level2_features.py)

### Proposed verified-provenance split

1. Obtain a development provenance manifest before creating a training
   or validation partition. Record source hashes, collection campaign
   and environment, original capture files and UTC bounds, and the
   exporter version and configuration. Use verified session IDs if
   available. A tuple with a validated timeout and timestamps can
   support a session grouping policy within a known capture.
2. Normalize each candidate's fields without labels or fitted state.
   Aggregate exact vectors and their row and class counts. Connect
   all rows sharing a vector, capture, or verified session, including
   links spanning multiple captures. Assign connected components as
   indivisible groups. Save seed, manifest reference and hashes,
   ordered feature contract, boundaries, group sizes and fold support
   alongside the plan. The reusable APIs are `plan_vector_folds`,
   `plan_capture_folds`, and `plan_capture_holdout`. Chronological
   boundaries must come from verified capture times or windows.
3. Preregister a whole-capture or chronological development holdout
   and validate its boundaries. If a connected group crosses a named
   holdout boundary, the planner rejects the plan. If there are too
   few independent groups, either partition lacks adequate support,
   or one component dominates, report infeasibility. Compute exact,
   session and capture overlap separately. The caller supplies and
   verifies the provenance. IDs alone cannot establish campaign
   independence.
4. Inside a feasible development plan, do feature selection, fitting,
   calibration, and threshold selection using appropriate training
   subsets only. Use fresh evidence for any claim about
   generalization, because G15 already used v2 labels to study the
   proposed features. The reserved independent benchmark stays sealed
   until the final protocol and model are frozen.
   [Split planner and checks](../../../ml/level2_splits.py) · [G13 evaluation plan](LEVEL_2_DATA_STRATEGY.md#leakage-safe-evaluation-plan)

The v3 ToN-IoT release is a possible separately approved development
input. It is a fresh extraction from the same source lineage, with
27,520,260 flows and absolute start and end timestamps in Unix
milliseconds. V2 has 16,940,496 flows. Matching a timestamped v3 row to
an untimestamped v2 row requires a verified crosswalk. A comparison
between time blocks within v3 would measure temporal transfer within
the source campaign. For capture-level evaluation, seek verified
capture-file provenance or separate authorized development campaigns.
Neither release substitutes for the reserved benchmark.
[UQ v3 dataset DOI](https://doi.org/10.48610/44d7c5e) · [V3 release and counts](https://staff.itee.uq.edu.au/marius/NIDS_datasets/) · [V3 extraction and timestamp method](https://arxiv.org/html/2503.04404#S4)

## Readiness decision

Use v2 for descriptive feature research and exporter checks. The current
release leaves capture and session independence unresolved and the
non-port projections retain large ambiguous groups. Before training,
verify development capture provenance and test the portable fields
against matched exporter fixtures. A separately approved timestamped
development release can support a temporal test within its lineage.
Independently sourced development captures with verified boundaries
are the stronger route for validating transfer. Keep raw ports out of
the first transferable feature contract until evidence from those
captures supports using them.

## Reproduce on the development release

Use Python 3.12.3 and the G14 file in the existing ignored directory.
The command is pinned to that source and writes only aggregate JSON
and temporary local runs.

```powershell
$release = 'data/level2/nf-ton-iot-v2'
& .\.venv\Scripts\python.exe -B -m ml.compare_level2_features --prefix 250000 |
    Set-Content -LiteralPath "$release/g15-prefix.json" -Encoding utf8
& .\.venv\Scripts\python.exe -B -m ml.compare_level2_features --prefix 250000 --set core --set core_lengths_flags --chunk-mib 32 |
    Set-Content -LiteralPath "$release/g15-two-set-prefix.json" -Encoding utf8
& .\.venv\Scripts\python.exe -B -m ml.compare_level2_features --sample 250000 --diagnose-folds core_lengths_flags |
    Set-Content -LiteralPath "$release/g15-sample.json" -Encoding utf8
& .\.venv\Scripts\python.exe -B -m ml.compare_level2_features --full --set core --set core_lengths_flags --chunk-mib 32 |
    Set-Content -LiteralPath "$release/g15-full.json" -Encoding utf8
& .\.venv\Scripts\python.exe -B -m unittest discover -s tests
```

All **112 Python tests** and **22 frontend tests** passed. The frontend
production build passed. The Level 1 artifact matched its frozen
checksum. G15 used only the NF-ToN-IoT-v2 development CSV and synthetic
fixtures for the new analysis and tests. The reserved
`NF-CSE-CIC-IDS2018-v2` benchmark and its derivatives stayed sealed.
