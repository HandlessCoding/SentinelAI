# G24 IoT-23 capture reconciliation and training feasibility

## Decision

Stop before fitting. The local Kaggle export is consistent with an IoT-23 v1
derivative. The duration-free contract makes more flows eligible, but the available
validation files contain only one original capture with attacks. The negative labels
in infected captures, full device lineage, and the exact export and label-rule
versions also remain unverified. Logistic Regression, Random Forest, calibration,
and threshold selection were skipped. There are no new recall, false-positive rate,
precision, balanced accuracy, or per-capture performance results.

## Reconciliation of the 23 CSVs

The G23 inventory recorded 47,386,086,562 bytes (47.39 GB) across 23 CSVs. The Kaggle
listing identifies its upload as version 1 and declares CC0. The publisher identifies
the underlying release as IoT-23 v1.0.0, with 20 infected recordings and three
dedicated benign device recordings. The publisher's release carries attribution
terms. The Kaggle upload version is the repackager's version. Conversion code, the
original payload checksums used by the uploader, and the uploader's authority to
change the underlying terms could not be verified. Keep the CSVs local and cite
Garcia, Parmisano, and Erquiaga (2020) for the underlying research dataset.
[Kaggle upload](https://www.kaggle.com/datasets/surajsooraj26/iot-23) ·
[Publisher release and label tables](https://www.stratosphereips.org/datasets-iot23) ·
[Versioned v1 deposit](https://zenodo.org/records/4743746)

Each number below maps to `datasetN.csv`. The `Honeypot` suffixes use the official
`CTU-Honeypot-Capture-` prefix. The other runs use `CTU-IoT-Malware-Capture-`. Dates are
UTC dates of the first observed timestamp or sample. An exact count match means the
full local nonzero detailed-label histogram matches the published one, with binary
label case normalized. Byte identity and individual labels require source-file verification.
The sampled mappings rely on the timestamp window and observed labels, so their
complete conversion, missing rows, and label counts remain unknown. Preserve each
original run ID. The publisher's v2 documentation describes eight benign files
derived from the same three original benign device recordings, so those fragments
add no independent groups. [Publisher capture and label tables](https://www.stratosphereips.org/datasets-iot23) ·
[Publisher v1 file catalog](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/) ·
[Publisher v2 release metadata](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/README.html)

| CSV | Original run | Device or reported family | Date | Rows examined | Evidence |
| --- | --- | --- | --- | ---: | --- |
| 1 | Honeypot 4-1 | Philips Hue | 2018-10-25 | 452 | Full, all benign |
| 2 | Honeypot 5-1 | Amazon Echo | 2018-09-21 | 1,374 | Full, all benign |
| 3 | Honeypot 7-1 | Somfy smart lock | 2019-07-03 | 130 | Full, all benign |
| 4 | 9-1 | Hajime | 2018-07-25 | 13,377 | Sample |
| 5 | 8-1 | Hakai | 2018-07-31 | 10,403 | Exact counts |
| 6 | 7-1 | Linux.Mirai | 2018-07-20 | 15,086 | Sample |
| 7 | 60-1 | Gafgyt | 2019-09-20 | 15,943 | Sample |
| 8 | 52-1 | Mirai | 2019-03-08 | 13,427 | Sample |
| 9 | 49-1 | Mirai | 2019-02-28 | 13,207 | Sample |
| 10 | 48-1 | Mirai | 2019-02-28 | 13,308 | Sample |
| 11 | 44-1 | Mirai | 2019-01-10 | 237 | Exact counts |
| 12 | 43-1 | Mirai | 2019-01-10 | 67,321,809 | Exact counts, full G24 scan |
| 13 | 42-1 | Trojan | 2019-01-10 | 4,426 | Exact G23 counts, file absent in G24 |
| 14 | 39-1 | IRCBot | 2019-01-09 | 14,080 | Sample |
| 15 | 36-1 | Okiru | 2018-12-21 | 15,884 | Sample |
| 16 | 35-1 | Mirai | 2018-12-21 | 16,111 | Sample |
| 17 | 34-1 | Mirai | 2018-12-21 | 23,145 | Exact counts |
| 18 | 33-1 | Kenjiro | 2018-12-20 | 14,422 | Sample, detailed-label discrepancy |
| 19 | 3-1 | Muhstik | 2018-05-19 | 156,103 | Exact counts |
| 20 | 21-1 | Torii | 2018-10-03 | 3,286 | Exact counts |
| 21 | 20-1 | Torii | 2018-10-02 | 3,209 | Exact counts |
| 22 | 17-1 | Kenjiro | 2018-09-06 | 14,080 | Sample |
| 23 | 1-1 | Hide and Seek | 2018-05-09 | 1,008,748 | Exact counts |

The observed categories in the other sampled files are subsets of their matched
publisher tables. The three dedicated benign CSVs each have nine fewer records
than the publisher's headline capture totals (461, 1,383, and 139). The reason is
unverified. The sampled
`dataset18.csv` contains `Okiru`, whereas the corresponding 33-1 table lists
`Okiru-Attack`. Preserve those raw values. G23's SHA-256 and full counts identify
the previously available `dataset13.csv` as consistent with 42-1, with 4,420
benign-labeled and six malicious rows. This run did not count toward live coverage.
[Publisher label tables](https://www.stratosphereips.org/datasets-iot23)

The formerly locked `dataset12.csv` opened read-only in G24. After a bounded
sample supported the Mirai 43-1 mapping, a single streaming pass scanned all
9,430,583,144 bytes. All 67,321,809 rows parsed with valid timestamps. The first
and last observed timestamps were 2019-01-10 18:22:53.721089 and 19:28:24.180328
UTC, respectively (minimum and maximum, since the file has 39,424 timestamp
backsteps). It contained 20,574,934 benign-labeled and 46,746,875 malicious-labeled
records. The six malicious counts matched the published table exactly.
[Publisher's capture label tables](https://www.stratosphereips.org/datasets-iot23)

| 43-1 attack category | Count |
| --- | ---: |
| `C&C` | 3,498 |
| `C&C-FileDownload` | 14 |
| `DDoS` | 65,803 |
| `FileDownload` | 1 |
| `Okiru` | 8,765,885 |
| `PartOfAHorizontalPortScan` | 37,911,674 |

Duration was unset in 67,250,964 rows (99.89%). All four packet and IP byte
counters were present and passed unsigned-integer parsing. The local SHA-256 is
`8dac6b3cb9c3167dbc67ed487648342a46e1bfc6285c8af3b8c6f0c356023fab`. The file stayed
outside the prespecified cohort and was audited separately for inventory and
integrity. Its size, rule-derived labels, and unresolved physical-device lineage
make a post-audit substitution insufficient to clear the gates.

## Label authority and portable features

The publisher used analyst review and Flaber rules applied to Zeek flow records.
The public rule sheet shows predicates on response port and connection state, and
the label descriptions cite shared ports, similar byte lengths, known endpoints,
and response payload sizes for some categories. The exact rule revision for each
CSV and the review history behind its negative labels are unavailable. Consequently,
the counts below say **benign-labeled** when the source uses that label. Verification
of unmatched background flows remains open. Empty or
unknown targets are separately counted and excluded. All seven audited files
contained explicit binary labels on the parsed rows.
[Publisher labeling method and category definitions](https://www.stratosphereips.org/datasets-iot23) ·
[Publisher's rule spreadsheet](https://docs.google.com/spreadsheets/d/1HRqgKJp0XoSUIfW3rCQKoD_LnSCJ1k-k61PndJXWq_o/edit#gid=0) ·
[Flaber](https://github.com/stratosphereips/flaber)

The duration-free contract uses `proto` (TCP or UDP), packet counts `orig_pkts` and
`resp_pkts`, and IP octet counts `orig_ip_bytes` and `resp_ip_bytes`. Direction is
Zeek originator to responder and reverse, and the octet counters are at the IP level.
A future Rust exporter must validate orientation, TCP/UDP eligibility, and packet
and IP byte accounting against the same flow fixtures. Treat unset duration as
absent, and keep measured zero duration valid. The duration-free contract omits
duration and any indicator of its absence. A complete-duration diagnostic requires
an observed nonnegative duration in seconds. It is only an eligibility comparison.
Use IP addresses, transport ports, and exact timestamps only for group diagnostics.
Exclude UID, category and binary label, service, connection state, history, payload
byte fields, and inferred device identity from the primary contract. Packet and IP
byte counters can still correlate with label rules and capture identity.
[Zeek connection log fields](https://docs.zeek.org/en/current/scripts/base/protocols/conn/main.zeek.html#type-Conn::Info)

## Prespecified cohort and gate results

G23 showed 30 malicious records across Torii runs 20-1 and 21-1, below the G20
per-role minimum. The replacement comparison role was assigned to Muhstik before
the feature/overlap scan, based on historical counts. The other roles were fixed
before the scan and no replacements were made once the Trojan file was found
absent. The criteria remained at least 1,000 eligible examples of each class in
each role, reviewable negatives, at least two original positive runs in final
development validation, retention of at least half of each verifiably labeled
class and each category with at least 100 source rows, and zero copied or linked
sessions across roles. Device lineage and applicable label integrity must also
support the proposed claim. [G20 gate design](LEVEL_2_CAPTURE_DATA_STRATEGY.md)

Each count pair is **benign-labeled / malicious-labeled**. G24 read 1,200,355
records across seven files (178,599,344 bytes) for this scan. All seven matched
their full G23 SHA-256 pins. The duration-free contract retained 1,181,592
records (98.44%). Requiring observed duration retained 303,833 (25.31%).

| Role | Original capture or device | Observed | Duration-free | Duration required | Dedicated benign eligible, duration-free |
| --- | --- | ---: | ---: | ---: | ---: |
| Fit | Hue 4-1, Hide and Seek 1-1 | 469,727 / 539,473 | 452,306 / 539,473 | 21,994 / 189,291 | 452 |
| Calibration | Echo 5-1, Hakai 8-1 | 3,555 / 8,222 | 3,469 / 8,222 | 3,161 / 2,056 | 1,288 |
| Comparison | Muhstik 3-1 | 4,536 / 151,567 | 3,329 / 151,567 | 3,309 / 78,620 | 0 |
| Final dev validation | Somfy 7-1, Mirai 34-1, Trojan 42-1 (absent) | 2,053 / 21,222 | 2,004 / 21,222 | 1,084 / 4,318 | 81 |

Every duration-free role clears the numeric class and category-retention checks on
the available source labels. The 1,821 dedicated-benign, TCP/UDP-eligible records
are concentrated in three original device recordings, with no dedicated negative
capture available to the comparison role. All four roles rely on infected-run
negatives to support broader capture claims. The only readable validation run with
attacks is Mirai 34-1. Recovering Trojan 42-1 alone would add at most six reported
malicious flows, still leaving any capture-specific attack recall estimate for it
exploratory under the 100-row reporting floor. Requiring duration also fails class
retention in fit, calibration, and validation and category retention across all four
roles. In validation it retains just 13 of 14,394 DDoS rows and 11 of 122 horizontal
scan rows. The duration-free variable set retains all malicious rows and their
category counts shown here.

| Role | Raw attack category counts on readable captures |
| --- | --- |
| Fit | `C&C` 8, `PartOfAHorizontalPortScan` 539,465 |
| Calibration | `C&C` 8,222 |
| Comparison | `Attack` 5,962, `C&C` 8, `PartOfAHorizontalPortScan` 145,597 |
| Final dev validation | `C&C` 6,706, `DDoS` 14,394, `PartOfAHorizontalPortScan` 122 |

The label distribution shifts sharply between roles. For example, all 8,222
Hakai attacks use TCP and carry `C&C`, while 2,179 of its 2,181 benign-labeled
flows use UDP. In Mirai 34-1, 21,220 of 21,222 malicious flows use TCP, and 1,812
of 1,923 benign-labeled flows use UDP. A learner can exploit transport and capture
correlations even with endpoints excluded. Feature parity alone cannot remove this
source of bias.

## Exact overlap and independence

The duration-free schema yielded 5,018 distinct typed vectors among 1,181,592
eligible rows. It had 1,176,574 additional copies beyond one occurrence per key.
There are 1,177,973 rows in repeated-vector groups, including their first
occurrences. Forty-two vectors carry both
labels, affecting 1,135,689 rows. The 11 keys shared between validation and the
other roles affect 7,007 validation rows (30.17%), including 1,710 benign-labeled
rows and 5,297 malicious rows. There are 294 benign-labeled and 15,925 malicious
validation rows on novel keys. Dropping all seen keys would undermine the minimum
negative support and change the evaluated traffic mix. Keep these counts as
diagnostics instead of filtering on labels or trying to make the rates favorable.

Two direction-independent TCP/UDP five-tuples crossed roles, from calibration to
validation, covering 161 and 15 benign-labeled rows respectively. There were zero
cross-role matches when the key included the exact exported start time, and no
exact tuple/start repeats within the scanned files. The zero-linked-session gate
requires additional metadata tying records to physical devices, run families, and
environments.
The publisher documents one CTU campaign and Raspberry Pi collection for infected
runs. The public 34-1 scenario metadata identifies one unit, but a complete
physical-device and session map for the cohort is missing. Treat the roles as
capture-separated candidates in the same campaign with unresolved dependence.
[Publisher campaign description](https://www.stratosphereips.org/datasets-iot23) ·
[Publisher 34-1 scenario files](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-IoT-Malware-Capture-34-1/)

## Reproducibility and G25 recommendation

`ml/audit_iot23_kaggle.py` streams the fixed input list with a 200 MiB ceiling. It
rehashes the inputs as it reads them, preserves raw categories, and uses spilled
sorted key counts. Source records and generated reports remain under ignored
`data/`. The 23-file reconciliation reused existing full scans and deterministic
windows and added one streaming pass for the newly available file. To reproduce the cohort audit
with the local G23 `datasetN-bounded.json` checksum pins already available:

```powershell
& .\.venv\Scripts\python.exe -B -m ml.audit_iot23_kaggle
```

All 149 Python tests passed, including five new G24 tests. All 22 frontend tests
passed, and the production build succeeded. The Level 1 pipeline SHA-256 matched
its prior pin and the implementation had no G24 changes. The reserved 2018 data
was outside the audit inputs.

For G25, prepare one capture registry for an authorized, isolated controlled-lab
collection. Pair ordinary benign recordings with already recorded, independently
labeled attack traffic in matched collection conditions and export each recording
with a pinned Zeek configuration. Each original recording needs its source,
permission terms, device and session IDs, UTC coverage, file hash, and independently
reviewed event windows. Keep uncertain traffic in a separate target. Assign whole
device/session groups to fit, calibration, comparison, and validation before any
training. Collect enough reviewable positives and negatives for every role to meet
the G20 floors, including two original positive runs in final validation. Use the
current feature schema as a candidate and preregister per-capture and known/novel
vector reporting. Keep the ≥95% recall and ≤5% false-positive rate as measurement
targets. The Level 1 artifact and the reserved 2018 benchmark are outside this work.
