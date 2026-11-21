# G14 · NF-ToN-IoT-v2 acquisition and quality audit

## Scope and provenance

G14 follows the [Level 2 data strategy](LEVEL_2_DATA_STRATEGY.md) and audits
only the standalone **NF-ToN-IoT-v2** development release. The University
of Queensland (UQ) publishes it as record `UQ:38a2d07`. The authors used
nProbe to extract NetFlow v9 fields from the ToN-IoT network captures
created at the UNSW Canberra cyber range. Their labeling method matched
endpoint addresses, ports, and protocol to published attack events.
Unmatched flows were recorded as benign. Release counts can verify
acquisition consistency. They cannot independently verify the original
labels or characterize current production networks. [UQ dataset DOI](https://doi.org/10.48610/38a2d07) · [UQ file and usage terms](https://rdm.uq.edu.au/files/a4ad7080-ef9c-11ed-a964-b70596e96ad5) · [Extraction and labeling method](https://arxiv.org/html/2101.11315#S3.SS2) · [Parent ToN-IoT documentation](https://research.unsw.edu.au/projects/toniot-datasets)

The release permits academic research reuse with citation to Sarhan,
Layeghy, and Portmann's *Towards a Standard Feature Set for Network
Intrusion Detection System Datasets*. Commercial use calls for agreement
with the authors. The project stores the data, audit output, and temporary
runs under the ignored local directory
`data/level2/nf-ton-iot-v2/` on D:. The reserved NF-CSE-CIC-IDS2018-v2
campaign and its derivatives stayed outside acquisition and development.
[UQ terms](https://rdm.uq.edu.au/files/a4ad7080-ef9c-11ed-a964-b70596e96ad5) · [Paper DOI](https://doi.org/10.1007/s11036-021-01843-0)

## Acquisition and integrity

Downloaded the standalone archive from UQ Research Data Manager after
approval. It contains the main CSV and `NetFlow_v2_Features.csv`, a
43-field dictionary. Both payloads matched the SHA-1 manifest bundled
by the publisher and their ZIP CRC-32 checks. The archive tags covered
by the tag manifest also verified. Locally recorded SHA-256 digests
identify this exact copy.

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `NF-ToN-IoT-v2.zip` | 168,120,179 | `69dd3b8bd59e23f0718dfc69b2757cb6ca08fe2c4c1d4fd126b8bbd204bbbad2` |
| `NF-ToN-IoT-v2.csv` | 2,676,491,000 | `7751fb955ca50a2c113ec455eddd39ca23fcfa99eb1ab488c4526c43c2a20081` |
| `NetFlow_v2_Features.csv` | 2,115 | `f20e86a939f9eb53b06ace15de4cc977ed61c02e538c6465efe72b635448e939` |

The CSV's publisher-manifest SHA-1 is
`c0e014512c9a825146c52982d3cf12d3fce1ccc9`. The expanded CSV is
2.68 GB (2.49 GiB). This is the measured size of the delivered copy.
The paper's historical table lists 2.47 GB. The input header contains 45
columns and matches the 43 published NetFlow field names plus `Label`
and `Attack`. [UQ release](https://rdm.uq.edu.au/files/a4ad7080-ef9c-11ed-a964-b70596e96ad5) · [Published feature list and sizes](https://arxiv.org/html/2101.11315#S3.T1)

## Full release findings

The audit read **16,940,496 records** across 45 columns. The CSV SHA-256
matched the extracted copy above. The observed schema, binary class
counts, and category counts matched UQ's release description.
[UQ release counts](https://staff.itee.uq.edu.au/marius/NIDS_datasets/) · [Publication Table 5](https://arxiv.org/html/2101.11315#S3.T5)

| Binary class | Records | Share of all records |
| --- | ---: | ---: |
| Benign | 6,099,469 | 36.01% |
| Attack | 10,841,027 | 63.99% |

| Attack category | Records | Share of attack records |
| --- | ---: | ---: |
| Scanning | 3,781,419 | 34.88% |
| XSS | 2,455,020 | 22.65% |
| DDoS | 2,026,234 | 18.69% |
| Password | 1,153,323 | 10.64% |
| DoS | 712,609 | 6.57% |
| Injection | 684,465 | 6.31% |
| Backdoor | 16,809 | 0.16% |
| MITM | 7,723 | 0.07% |
| Ransomware | 3,425 | 0.03% |

The observed category and binary label agreed on every record. Scanning
and XSS account for over half of the attack rows. Category support
will also vary with how those rows concentrate within capture groups.

### Column types and quality signals

| Observed representation | Columns |
| --- | --- |
| IPv4 address text | `IPV4_SRC_ADDR`, `IPV4_DST_ADDR` |
| Decimal numeric text | `L7_PROTO`, `SRC_TO_DST_SECOND_BYTES`, `DST_TO_SRC_SECOND_BYTES` |
| Integer numeric text | All 39 other numeric fields, including `Label` and the six predictors |
| Category text | `Attack` |

Every column had **zero missing cells**. There were zero malformed
numeric or IPv4 values, nonfinite numbers, negative numeric values,
or values above the audited protocol, port, TTL, and label bounds.
All rows passed the six-field adapter's type and range checks.
The ignored JSON report gives the type counts, missing count, zero
count, and numeric range for each field.

- **Zero duration.** 13,813,074 rows (81.54%) had a duration of 0 ms.
  Timestamp resolution or single-packet flows can produce a zero
  duration. It provides little timing separation among those rows.
- **Directional zeros.** 6,269,875 rows (37.01%) had both reverse packet
  and reverse byte counters at zero. The audit found zero rows with
  both packet counts zero or with a zero packet count disagreeing with
  a zero byte count in the same direction.
- **Counter semantics.** `IN_BYTES` reaches as low as 4 while every
  row reports at least one forward packet. Four octets is shorter
  than an IPv4 header. The value passes the integer contract and
  leaves IP-layer accounting parity unresolved. Resolve the exporter
  behavior or omit the byte fields from a cross-export contract before
  training. [IPFIX octet definition](https://www.iana.org/assignments/ipfix/ipfix.xhtml) · [IPv4 header definition](https://www.rfc-editor.org/rfc/rfc791.html)
- **Other zeros.** `L7_PROTO` was zero in 10,290,531 rows (60.75%).
  Each TTL field was zero in 10,889,627 rows (64.28%). The audit
  preserves these as literal values. Their interpretation as measured,
  unavailable, or unclassified values needs exporter evidence.

### Exact duplicates and conflicting labels

| Check | All 45 decoded columns | Six canonical predictor fields |
| --- | ---: | ---: |
| Distinct records or vectors | 16,940,496 | 686,858 |
| Repeated occurrences beyond the first | 0 | 16,253,638 |
| Groups appearing more than once | 0 | 192,444 |
| All rows in repeated groups | 0 | 16,446,082 |
| Largest group | 1 | 3,589,712 |

All original rows are distinct. With the common-feature projection,
**97.08% of records** are in repeated groups, and the largest group
contains **21.19%** of the dataset. **7,401 vectors carry both binary
labels**, covering **11,403,591 rows (67.32%)**. Those rows comprise
5,178,642 benign and 6,224,949 attack records. A deterministic
classifier would receive identical inputs for those opposite labels.
The audit leaves the source records, labels, and weights intact.

## Grouping and leakage decision

The inspected CSV header contains no absolute timestamp, capture
identifier, scenario identifier, or session ID. There is also no
`Dataset` column because this is a standalone export. The parent
ToN-IoT documentation lists timestamped events. The v2 release does
not supply a validated way to assign each exported flow to those
events. A later investigation could assess publisher-provided capture
metadata or a timestamped export from the development lineage.
[Parent ToN-IoT release](https://research.unsw.edu.au/projects/toniot-datasets) · [Temporal NetFlow paper](https://arxiv.org/abs/2503.04404)

Same-feature grouping guards against exact predictor repeats crossing
folds. It leaves scenarios, sessions, captures, and other related flows
potentially shared between folds. A five-tuple can recur and cannot
identify distinct sessions without reliable time and exporter
information. Directional durations are elapsed intervals. CSV order
supplies no documented timeline. A credible within-source split needs
verified capture, session, or scenario grouping plus exact-vector
isolation. If provenance cannot be recovered, use enough independently
sourced development captures for whole-source validation before model
selection. [Grouping plan](LEVEL_2_DATA_STRATEGY.md#leakage-safe-evaluation-plan)

The biggest predictor group is large enough to distort fold sizes and
class balance. The conflict counts also make the six-field projection
a weak basis for assuming those classes can be separated. Use the
release for schema and data-quality work. Before a leakage-resistant
training and validation experiment, verify grouping provenance and
review whether additional portable features can distinguish these
flows. Keep the independent evaluation campaign sealed during those
decisions.

| Leakage risk | Level 2 handling |
| --- | --- |
| `Label` and `Attack` | Retain for target validation and reporting only. |
| Raw IP addresses, transport ports, and five-tuples | Exclude from predictors. They can identify the environment, roles, and scenarios, and were part of the release's labeling method. Keep only permitted local provenance for grouping or audit. |
| Capture, timestamp, row, and exporter identifiers | Exclude from predictors. Use verified metadata for grouping when available. |
| `L7_PROTO`, DNS transaction ID, FTP code, TTL, TCP flags and window sizes, and exporter-derived statistics | Defer. These can encode host, application, or instrument behavior, and their availability and semantics vary by exporter. |
| Duration and directional counters | Validate semantics and test on independent capture contexts. Even portable measurements can correlate with the testbed or exporter. |

## Preprocessing contract

`flow-core-v1` uses six fields, in the order below. The adapter selects
and validates their values, preserving source orientation, before any
future fitting. It accepts unsigned integer values or exact ASCII CSV
integer spellings, including lossless forms like `24.0`. It rejects
missing, fractional, negative, and out-of-range values. Measured zero is
retained. Rejections are attributed to the first invalid field per row.
No learned scaling, imputation, encoding, or classifier is included.
[Flow adapter](../ml/level2_flow_schema.py)

| Canonical field | UQ column | Definition and type |
| --- | --- | --- |
| `protocol` | `PROTOCOL` | Unsigned 8-bit IP protocol number. |
| `duration_ms` | `FLOW_DURATION_MILLISECONDS` | Exporter's flow duration in integer milliseconds, stored as an unsigned 64-bit value. |
| `src_to_dst_packets` | `IN_PKTS` | Unsigned 64-bit packet count in the exported source-to-destination direction. |
| `dst_to_src_packets` | `OUT_PKTS` | Unsigned 64-bit packet count in the reverse direction. |
| `src_to_dst_octets` | `IN_BYTES` | Unsigned 64-bit exported byte count in the source-to-destination direction. |
| `dst_to_src_octets` | `OUT_BYTES` | Unsigned 64-bit exported byte count in the reverse direction. |

nProbe documents `IN` as source-to-destination and `OUT` as reverse.
The bundled dictionary describes both directional duration fields as
client-to-server. nProbe's definitions distinguish their directions.
The adapter uses total flow duration.
The source endpoint need not match Zeek's originator. Zeek's
`orig_ip_bytes` and `resp_ip_bytes` include IP headers, while its
`orig_bytes` and `resp_bytes` describe transport payload. Flow start and
stop rules, timeouts, sampling, inference of orientation, and conversion
of fractional seconds to milliseconds still need verification on shared
fixtures. A Rust adapter can use the same integer widths and rejection
rules. Require byte accounting, units, direction, and record boundary
parity before native Rust or Zeek records use this contract.
[nProbe information elements](https://www.ntop.org/guides/nprobe/flow_information_elements.html) · [IPFIX information elements](https://www.iana.org/assignments/ipfix/ipfix.xhtml) · [Bidirectional orientation](https://www.rfc-editor.org/rfc/rfc5103.html#section-5) · [Zeek connection fields](https://docs.zeek.org/en/current/scripts/base/protocols/conn/main.zeek.html#type-Conn::Info)

## Reproduce the audit

Run from the repository root in PowerShell using the existing Python
environment. Obtain only the approved standalone release via its UQ
landing page and place the extracted CSV in the ignored directory above.

```powershell
$auditPath = 'data/level2/nf-ton-iot-v2/audit.json'
& .\.venv\Scripts\python.exe -B -m ml.audit_level2_data --progress |
    Set-Content -LiteralPath $auditPath -Encoding utf8
if ($LASTEXITCODE -ne 0) { throw "Dataset audit did not match the published release." }
& .\.venv\Scripts\python.exe -B -m unittest discover -s tests -p 'test_*level2*.py' -v
```

The standard-library audit reads **4,096 records per chunk**, aggregates
repeated cell spellings before type checks, and writes sorted duplicate
runs on the same drive as the input. It retains at most
an estimated 32 MiB of entries per duplicate counter before spilling.
The merges open a bounded number of files. Exact key bytes are compared
across chunks, and temporary runs are removed when processing finishes.
Raw duplicates compare every decoded column, including the two labels.
Common-feature groups compare the six validated typed integers. A
conflicting group has both binary labels. Counts distinguish repeated
occurrences beyond the first, all rows in repeated groups, and all rows
in conflicting groups. Type counts distinguish blank cells, numeric
spellings, nonfinite values, and malformed values. The JSON report
contains aggregates rather than source rows. [Audit command](../ml/audit_level2_data.py) · [Exact duplicate aggregation](../ml/level2_audit_storage.py)

The full scan and exact merge took **11 minutes 31 seconds** in the
local Python 3.12.3 environment. At the 8.25 million record checkpoint,
the audit process's peak working set was approximately 78 MiB.

The 19 new synthetic tests cover feature validation, storage merges and
cleanup, and full CSV summaries across chunk boundaries. The complete
suite passed **90 Python tests** and **22 frontend tests**. The frontend
production build passed. The frozen Level 1 pipeline matched its recorded
SHA-256. G14 produced no new fitted model.
