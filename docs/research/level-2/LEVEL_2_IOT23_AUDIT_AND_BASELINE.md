# G21 · IoT-23 v2 acquisition, capture audit and baseline decision

## Decision

**Training did not proceed.** The indexed official catalog exposed
candidate files and capture metadata. Live CVUT requests for the
release documentation and named flow artifacts timed out before
returning HTTP headers. No v2 flow files or PCAPs were acquired.
Exact file lengths, revisions, flow and rule SHA-256 values, and
v2-specific usage terms remain unverified. Capture-level model
feasibility is therefore **undetermined**. The evidence below
comes from publisher metadata and separately identified v1
summaries. The audit code was exercised on synthetic fixtures.
[G20 capture strategy](LEVEL_2_CAPTURE_DATA_STRATEGY.md) · [Official v2 catalog](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/)

## Acquisition and provenance

The approved scope was up to 512 MiB of verified official v2
flow-only files on D:. DNS resolved the publisher host. Attempts
to retrieve live metadata included the release README and HTTPS
`HEAD` requests for two specific labeled logs. Both the Mirai
`34-1` and Echo `5-1` requests returned curl connection
timeout code 28. The publisher's backup listing points to the
original release's bulk flow archive, which exceeds the budget
and belongs to a different version.

The original release explicitly states CC BY. The v2 README
describes a revised labeling release in progress and requests
citation. It does not state separate terms for the revised
annotations. A legacy individual scenario also includes an
authorization notice. Preserve attribution and confirm reuse
terms for the particular v2 artifacts before acquisition.
The README's sample hashes for malware runs identify the malware
sample and cannot verify a flow export. Capture IDs, log and rule
filenames, exact lengths, last-modified or publisher version,
publisher checksums when available, and local SHA-256 values
belong in the acquisition manifest. Keep original logs and label
configuration sidecars in the ignored acquisition directory.
[Original release terms](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/) · [V2 README and changelog](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/README.html) · [Legacy scenario notice](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-IoT-Malware-Capture-34-1/) · [Publisher backup listing](https://www.stratosphereips.org/datasets-faq)

### Initial candidate inventory

The inventory below contains publisher listings only. No
listed file has a verified byte count or local digest. Match
the root-level labeled export to its own `labels.config`.
Export listings use both `-zeek-conn-log.labeled` and
`-zeek-conn.log.labeled` file endings. Some labeled filenames
still carry 2019 modification dates inside the v2 directory.
The listing alone cannot identify which labeling revision
produced those rows. A nested `conn.log` may be an unlabeled
export of the same original capture.
[Example v2 labeled and nested files](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/CTU-IoT-Malware-Capture-3-1/) · [Nested log listing](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/CTU-IoT-Malware-Capture-3-1/zeek-labeled/)

| Proposed role | Original capture or group | Listed size and availability |
| --- | --- | --- |
| Fit | Malware `1-1` (Hide and Seek), malware `3-1` (Muhstik), benign Hue `4-1` | Root labeled logs listed at 138M, 23M, and 60K, respectively. [1-1](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/CTU-IoT-Malware-Capture-1-1/) · [3-1](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/CTU-IoT-Malware-Capture-3-1/) · [4-1](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/CTU-Honeypot-Capture-4-1/) |
| Calibration | Malware `8-1` (Hakai), benign Echo `5-1` | Echo's root labeled log is listed at 178K. The exact Hakai labeled artifact and size remain unconfirmed. [Release index](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/) · [5-1](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/CTU-Honeypot-Capture-5-1/) |
| Model comparison | Malware `20-1` and `21-1` (Torii) | `20-1` labeled log listed at 410K. `21-1` has a publisher capture README. Its exact labeled artifact and size remain unconfirmed. This role needs separately verified benign evidence. [20-1](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/CTU-IoT-Malware-Capture-20-1/) · [21-1](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/CTU-IoT-Malware-Capture-21-1/README.html) |
| Locked development validation | Malware `34-1` (Mirai), malware `42-1` (Trojan), benign Somfy `7-2` through `7-6` | `34-1` listed at 2.9M. Exact size of `42-1` and every Somfy shard remains unconfirmed. Somfy examples `7-2`, `7-5`, and `7-6` list 6.7K, 6.9K, and 6.7K. Leave the 1.2G `7-1` labeled file out of this acquisition. Keep all Somfy shards in the validation group. [34-1](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/CTU-IoT-Malware-Capture-34-1/) · [7-2](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/CTU-Honeypot-Capture-7-2/?C=S%3BO%3DA) · [7-5](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/CTU-Honeypot-Capture-7-5/) · [7-6](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/CTU-Honeypot-Capture-7-6/?C=N%3BO%3DD) · [7-1](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/CTU-Honeypot-Capture-7-1/?C=N%3BO%3DD) |

The listed subset accounts for roughly 165 MiB based on the
directory's rounded sizes. This is a subtotal. Recheck all
lengths and enforce a combined 512 MiB transfer cap before any
approved acquisition. No substitute, PCAP, or complete archive
was downloaded.

## Capture and label evidence

The v2 publisher reports 20 malware files and eight benign
files. The eight benign files trace to three original devices.
Keep the six Somfy files together. The catalog and the
Somfy `7-2` README disagree about its host and gateway values.
Its filename agrees with the catalog's host value. Resolve
that inconsistency using original capture provenance and the
logged times. The discrepancy makes address values unreliable
as device identity evidence. Separate capture IDs also do not
prove that the same Raspberry Pi or lab infrastructure was
absent from adjacent roles.
[V2 capture summary](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/README.html) · [Somfy 7-2 metadata](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/CTU-Honeypot-Capture-7-2/?C=S%3BO%3DA)

The publisher's **v1 summaries** show why mixed-run negatives
and rare categories need careful auditing. These are historical
label counts. They do not verify v2 labels or eligibility.

| Run | Published v1 `Benign` | Selected published v1 attack labels |
| --- | ---: | --- |
| Malware `8-1` | 2,181 | 8,222 C&C |
| Malware `20-1` and `21-1` combined | 6,465 | 30 C&C-Torii |
| Malware `34-1` | 1,923 | 6,706 C&C, 14,394 DDoS, 122 horizontal-scan flows |
| Malware `42-1` | 4,420 | 3 C&C–file download and 3 file download |

The Torii counts point to a serious risk for the 1,000-attack
comparison floor. The Trojan count also cautions against
interpreting a capture-level rate with a tiny attack denominator.
An independent IoT-23 v2 label reconstruction reports using
per-capture source-IP rules with overrides. The publisher's
labeler can match identifiers, ports and numeric flow fields,
and it supports empty labels when rules do not match. These are
reasons to verify the exact config and provenance before using
the binary labels. Review unrelated normal behavior in mixed
runs and distinguish it from a default label or a host-based
rule. Keep unknown, background, and unreviewed mixed-run
`Benign` rows outside the verified-negative denominator.
Preserve raw compound categories for coverage reporting.
[Publisher v1 per-run labels](https://www.stratosphereips.org/datasets-iot23) · [Publisher labeler](https://github.com/stratosphereips/netflowlabeler) · [Independent label reconstruction](https://github.com/NemanjaDomanovic/iot-label-validation)

## Feature audit and validation preflight

The offline auditor checks local, individually SHA-256-pinned
Zeek TSV logs. It records row counts, declared fields and types,
start-time bounds, label and category counts, missing values,
numeric anomalies, and within-capture duplicates. Disk-backed
exact grouping counts cross-role overlap for native vectors,
a no-IP-bytes variant, direction-independent TCP/UDP
five-tuples, matching tuple-and-start keys, complete
records, and original-group-scoped UIDs. It reports aggregate
counts without printing raw flow rows. Matching start keys
need provenance review. Time-separated repeated vectors or
tuples by themselves do not prove shared sessions.
[Audit CLI](../../../ml/audit_iot23_captures.py) · [Synthetic fixtures](../../../tests/test_iot23_capture_audit.py)

The first candidate contract uses TCP/UDP protocol, native
Zeek duration, originator and responder packet totals, and
IP-layer bytes per direction. Duration and Unix time are parsed
from decimal seconds into exact nanoseconds for comparisons.
Unset fields and zeros stay distinct. Restricting the first
contract to TCP/UDP keeps ICMP pseudo-port semantics out of
the overlap keys. Report excluded protocols by capture and
class before deciding whether this loss is acceptable.
The original addresses, ports, absolute times, capture/device
IDs, UIDs, labels and rule outputs are audit metadata.
`orig_bytes` and `resp_bytes` are Zeek payload counters,
distinct from the selected IP-layer totals. Compare a
no-IP-bytes projection to assess reliance on counter semantics
or labeling rules. Zeek direction can change under its
connection heuristic. A future Rust collector needs tests of
direction, flow timeout, partial captures and packet/byte
accounting on shared fixtures before equivalence can be claimed.
Do not map the export directly onto nProbe's `flow-core-v1`.
[Zeek connection fields](https://docs.zeek.org/en/current/scripts/base/protocols/conn/main.zeek.html#type-Conn::Info) · [Zeek text formats](https://docs.zeek.org/en/current/log-formats.html) · [G20 feature compatibility](LEVEL_2_CAPTURE_DATA_STRATEGY.md#feature-compatibility)

The G20 gates still require at least 1,000 eligible records
of each class in each role, at least two original positive
capture groups in final validation, and retention of at least
half of each verified class and each reported attack category
with at least 100 source records. They also require disjoint
original or known-linked recording groups and review of
unexplained overlap. Freeze roles and eligibility before
scoring. Comparison must have approved negatives from a
compatible capture source, and the initial calibration plan
has too few attack-bearing groups for an independent
probability-calibration split. File names and record totals
cannot demonstrate independence or review the labels.
[G20 feasibility gates](LEVEL_2_CAPTURE_DATA_STRATEGY.md#feasibility-gates-before-fitting)

### Running the preflight after verified acquisition

Create an ignored local JSON manifest containing one object
per verified artifact. Each object supplies `capture_id`,
`original_group`, `device_group` (or `null` if unresolved),
`role` (`fit`, `calibration`, `comparison`, or `validation`),
`log` (relative file path), and `sha256`. Leave out
`negative_evidence` unless documented review covers the
explicit benign labels being counted in that log. The CLI
checks declared groups, counts and hashes. Authoritative
capture identity, exact v2 format, actual label quality,
and permissions still require separate review.

```powershell
& .\.venv\Scripts\python.exe -B -m ml.audit_iot23_captures data/level2/iot23-v2/captures.json
```

### Measured results and training decision

| Item | G21 result |
| --- | --- |
| Official v2 flows or bytes acquired | 0 |
| Official v2 record counts, label coverage, quality and exact overlap | Unmeasured |
| Software verification | Synthetic fixture tests exercise labeling, missing values, overlap, provenance and eligibility gates |
| Logistic Regression and Random Forest | Phase 4 was gated off. No models, thresholds, feature importances, or performance estimates were produced. |

## G22 recommendation

First obtain an authoritative, reachable source for the named
flow-only files, their exact revision, label rules and terms.
Check the planned Torii comparison counts and Somfy metadata
before committing to the pilot. If either cohort is inadequate,
use an independently documented replacement before model
selection or stop at feasibility.

If the IoT-23 release remains unavailable, prioritize identifying
an official flow-only **CTU-SME-11** subset with independent
device/run metadata, both classes, and resolvable label rules.
The publisher exposes Zeek-derived flows and a small summary
table, but the current version's smallest listed device archive
is 742.9 MB. A bounded flow-only subset is unverified. Inspect
the summary and file inventory before requesting a download.
**CTU-13** remains a potential source-native fallback. The
publisher's overview explicitly lists CC BY, resolving the
license gap recorded in G20. Its Argus semantics, weak host-based
positive labels, and unverified background still limit the
research claim. If neither source has a suitable subset, collect
authorized benign sessions across separately documented devices
and combine them with an independently labeled, compatible
offline capture only when the provenance and schema match
the proposed evaluation.
[CTU-SME-11 version and files](https://zenodo.org/records/7958259) · [CTU-13 publisher license](https://www.stratosphereips.org/datasets-overview/)

The frozen Level 1 application, model and official evaluation
remain separate from this work. The reserved
NF-CSE-CIC-IDS2018 evaluation benchmark stayed sealed.
