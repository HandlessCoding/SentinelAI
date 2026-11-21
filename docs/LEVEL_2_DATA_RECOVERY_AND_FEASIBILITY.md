# G22 · Capture data recovery and feasibility

## Decision

**A defensible training dataset is still unavailable.** The official
IoT-23 v2 service timed out on individual directory, flow, and label
configuration requests. For CTU-SME-11, the publisher summary and a
labeled Zeek excerpt were recovered and verified. The excerpt contains
766 flows from one device and one original capture. It cannot supply
four disjoint roles or the preregistered class support. The full
publisher summary cannot establish record-level coverage or session
independence. No model, probability calibration, or threshold was fit.
[G20 protocol](LEVEL_2_CAPTURE_DATA_STRATEGY.md) · [G21 blockers](LEVEL_2_IOT23_AUDIT_AND_BASELINE.md)

## IoT-23 v2 recovery

Six official HTTPS endpoints were checked, including both capture
directories and each directory's exact labeled log and label-rule file.
Each request had one retry, a four-second connection timeout, and a
five-second per-attempt limit. Both attempts on all six endpoints
returned curl timeout code 28 without HTTP headers. The publisher's
indexed directory listings verify the filenames and origin of the links
below. Their live availability, exact lengths, and SHA-256 values
remain unverified.

The v2 publisher documents revised labels, per-capture rule files,
and directories split from three original benign device recordings.
The original release says CC BY. The v2 README requests citation
and does not state separate terms for its revised annotations.
An original scenario README includes an authorization notice.
Confirm applicable terms for the specific v2 flow and rule files,
and verify which revision the files represent. Names, displayed dates,
and the malware-sample hashes in READMEs cannot verify flow bytes.
No IoT-23 flows or rule files were acquired.
[V2 catalog](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/) · [V2 README](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/README.html) · [Original release terms](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/) · [Legacy scenario notice](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-IoT-Malware-Capture-34-1/)

### Manual browser handoff

1. Open the official [Echo 5-1 directory](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/CTU-Honeypot-Capture-5-1/) and
   [Mirai 34-1 directory](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/CTU-IoT-Malware-Capture-34-1/)
   in a Windows browser. These are a benign-device file and a mixed-run
   candidate. Confirm the official hostname and read the capture README.
   If they also time out, record the error. The links below were checked
   against the publisher listings. The browser download itself remains
   untested.
2. Once the terms and release are confirmed, save the three files for
   each capture using **Save link as**. Preserve the original filenames
   under separate capture directories in
   `D:\Coding\Projects\SentinelAI\data\level2\iot23-v2\`.
   This pair is listed at about 3.1 MiB plus small sidecars.

   | Exact official artifacts | Browser links |
   | --- | --- |
   | Echo `CTU-Honeypot-Capture-5-1` (178K log) | [Labeled flow](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/CTU-Honeypot-Capture-5-1/2018-09-21-11-40-22-192.168.2.3-zeek-conn-log.labeled) · [Label rules](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/CTU-Honeypot-Capture-5-1/2018-09-21-11-40-22-192.168.2.3-labels.config) · [README](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/CTU-Honeypot-Capture-5-1/README.md) |
   | Mirai `CTU-IoT-Malware-Capture-34-1` (2.9M log) | [Labeled flow](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/CTU-IoT-Malware-Capture-34-1/2018-12-21-15-50-14-192.168.1.195-zeek-conn-log.labeled) · [Label rules](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/CTU-IoT-Malware-Capture-34-1/2018-12-21-15-50-14-192.168.1.195-labels.config) · [README](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/CTU-IoT-Malware-Capture-34-1/README.md) |

3. Check each browser download completed, keep its source URL, visible
   version or last-modified date, and exact byte count, then run the
   commands below from the project root. Use any publisher checksum to
   verify the file when available. The local SHA-256 pins the acquired
   bytes for later use. It does not authenticate an unspecified release.
   Keep the cumulative flow and metadata acquisition at or below
   512 MiB, including the 156,242 publisher file bytes already saved in
   G22. Skip PCAPs, nested unlabeled logs and bulk archives.

   ```powershell
   $g22Iot = 'data/level2/iot23-v2'
   Get-ChildItem -LiteralPath $g22Iot -Recurse -File |
       Select-Object Name, Length
   Get-ChildItem -LiteralPath $g22Iot -Recurse -File |
       ForEach-Object { Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName }
   ```

4. Report the saved locations so the same audit can verify the two logs
   before expanding to the rest of the candidates. This pair is a
   provenance and parser check. It provides no replacement for the
   independently supported fit, comparison, and validation cohorts.
   The later shortlist and held roles remain those in G20. In particular,
   legacy Torii summaries reported just 30 attack-labeled rows across
   the two intended comparison runs. Their v2 coverage still needs
   measurement before any experiment.
   [G20 proposed roles](LEVEL_2_CAPTURE_DATA_STRATEGY.md#proposed-development-partitions) · [Publisher's v1 label tables](https://www.stratosphereips.org/datasets-iot23)

## CTU-SME-11 fallback

The official Zenodo metadata API confirms release **1.0.0** and
**CC BY 4.0**. All 11 full device packages exceed 512 MiB individually.
The smallest is the Echo archive at **742,890,363 bytes**. The release
lists no separate full-device flow-only archive. None of the archives
was downloaded. The Stratosphere Laboratory also publishes a small,
labeled test excerpt in its Slips repository. Its README identifies it
as the first 5,000 packets of the Windows7full-3 recording on
2023-02-22. G22 retrieved only the resulting connection log and its rule
and README sidecars, along with the official Zenodo summary.
[Release inventory](https://zenodo.org/records/7958259) · [Version and rights metadata](https://zenodo.org/api/records/7958259) · [Publisher excerpt and lineage](https://stratospherelinuxips.readthedocs.io/en/develop/datasets.html#test18-malicious-ctu-sme-11-win)

### Verified acquisition

The Zenodo CSV matched the publisher MD5. Each Slips file matched
its publisher-listed Git blob ID and exact length. SHA-256 pins the
copies saved under ignored `data/level2/ctu-sme-11/`. The excerpt's
flow and label analysis use the same pinned bytes.

| File | Bytes | Local SHA-256 |
| --- | ---: | --- |
| `CTU-SME-11_summary_table.csv` | 1,953 | `c052dbe5795cecfd3be96e125fbcf1ad5f77c1f7da32959a73a6acd829181432` |
| `test18-malicious-ctu-sme-11-win/README.md` | 418 | `36ab220b1ee0abbff9f959776a0a9923b65a74ef4fcdd5ab09199f17c420fc7b` |
| `test18-malicious-ctu-sme-11-win/labels.config` | 6,435 | `1d5568102430962edd53d49c519a5f3319ec3f4b3d453dcaae1fa028f6e9c15a` |
| `test18-malicious-ctu-sme-11-win/conn.log.labeled` | 147,436 | `c4549138431e8827e5821f7f09ab5bdf758ec3eee5ee30c38fa8271e19b3fd94` |

[Official summary](https://zenodo.org/records/7958259/files/CTU-SME-11_summary_table.csv) · [README blob](https://api.github.com/repos/stratosphereips/StratosphereLinuxIPS/git/blobs/17d78a6c5345bf0bb385a0d9a092d1c60d281a7b) · [Rule blob](https://api.github.com/repos/stratosphereips/StratosphereLinuxIPS/git/blobs/b3b564bc1a0ccb1e86606b84bf7491ac88f04af0) · [Flow blob](https://api.github.com/repos/stratosphereips/StratosphereLinuxIPS/git/blobs/20f3a307c457b28c70111a1d8679eb4931b0340e)

### What the full summary and excerpt show

- **Publisher summary.** The 11 device totals add up to 99,993,509
  flows. The class totals reconcile per device and combine to 1,608,273
  benign, 98,319,252 malicious and 65,984 unknown. Each device reports
  at least 1,000 flows in each binary class over its full recording.
  One Ubuntu VM accounts for **99.46%** of the reported malicious
  flows. All 11 device windows have a common interval spanning almost
  the entire week on the publisher's clock. Different devices can
  observe the same events or shared traffic. Device totals and dates
  alone cannot establish independent sessions, class eligibility,
  category support, or transferable performance.
  [Publisher summary CSV](https://zenodo.org/records/7958259/files/CTU-SME-11_summary_table.csv)
- **Measured excerpt.** The 766 Zeek flows begin between
  2023-02-22 00:00:02.966990 UTC and 00:08:21.956000 UTC. The log
  contains 719 explicit malicious rows in a single published
  RemcosRAT exfiltration category, 44 explicit benign labels with
  unverified ground truth, and three unknown rows. The complete
  TCP/UDP candidate admits 718 malicious rows and zero verified
  benign rows. Five ICMP flows are outside the first contract,
  and six rows have unset duration. No full-row or capture-scoped
  UID repeats were found. There are 40 repeat occurrences beyond the
  first for the full predictor vector and 75 for the no-IP-bytes
  vector. TCP/UDP five-tuples repeat 479 times beyond the first,
  while tuple-plus-start keys have zero repeated occurrences. These
  are within-excerpt statistics. Cross-capture overlap is unmeasurable
  with one excerpt.
- **Measured shortcut risk.** The file contains two malicious
  rule clauses and both use destination IP. Benign rules use
  source or destination IP and some use protocol or destination
  port. All 719 malicious rows are TCP. Only three of the 44 rows
  labeled benign are TCP. The other benign-labeled rows are 36 UDP
  and five ICMP. Even the portable protocol feature could separate
  much of this short excerpt because of its collection and
  annotation. Record predicate field names and protocol/class
  counts in future audits. Keep addresses, ports, timestamps, UIDs
  and capture identity outside predictors. Rule outputs and
  `Unknown` or background traffic cannot supply verified negatives.

### Preflight and gates

The G21 CLI now verifies pinned label-rule sidecars and reports
predicate fields without printing their values. It also reports
protocol distribution by raw label confidence. To include a
sidecar, add both `label_rules` (relative `.config` path) and
`label_rules_sha256` to the [local manifest format](LEVEL_2_IOT23_AUDIT_AND_BASELINE.md#running-the-preflight-after-verified-acquisition).
This inventories label shortcuts. It does not replay rules or
independently certify labels. The excerpt was passed to the audit CLI
under its fit-role argument for the local smoke check. No fit cohort
was created and no model saw the excerpt.

```powershell
& .\.venv\Scripts\python.exe -B -m ml.audit_iot23_captures data/level2/ctu-sme-11/test18-malicious-ctu-sme-11-win/g22-excerpt-manifest.json
```

The G20 criteria remain frozen. Each role needs at least 1,000
eligible examples per class and reviewable negatives. Final development
validation needs at least two original positive capture groups. Keep
at least half of each verified class and named categories with at
least 100 source rows after eligibility filters. Check original groups,
device reuse, exact duplicate material, same-time tuples, and feature
overlap before fitting. Keep ordinary repeated vectors separate from
evidence of a copied or linked session. Train Logistic Regression and a
small Random Forest on the same portable schema only after passing
the gates. Calibration and cutoff selection use their designated
development captures. Final development validation stays untouched
by model and operating-point selection. No benchmark or live-network
performance can be inferred from this milestone.
[Audit implementation](../ml/audit_iot23_captures.py) · [G20 feasibility gates](LEVEL_2_CAPTURE_DATA_STRATEGY.md#feasibility-gates-before-fitting)

## Controlled-lab alternative

If the manual recovery yields inadequate support, move to a small,
authorized collection with supervisor-approved, already recorded
mixed traffic and independently documented positive windows.
Capture ordinary benign workloads on consented or purpose-built
devices in an isolated lab. Process approved prerecorded traffic
offline with the same pinned Zeek version and settings. Start with
matched mixed recordings that include benign activity and verified
incidents under comparable observation conditions. A synthetic alert
fixture may test ingestion and labels. It cannot stand in for measured
attack recall. No public or live attack traffic is required by this plan.

| Role | Target collection |
| --- | --- |
| Fit | At least two separately recorded runs covering more than one device or workload. Keep repeated recordings and their derivatives together. |
| Calibration | Separate runs containing verified normal behavior and positive windows. Use distinct groups for probability mapping and cutoff selection when support allows. |
| Model comparison | Separate capture and device groups with both verified classes. Use fixed cutoffs from calibration. |
| Final development validation | A separately recorded environment or device group, with at least two original positive capture runs and enough verified normal traffic to report FPR. Seal its rows and detailed labels once preflight aggregates pass. |

Before analysis, preserve an immutable manifest with the sensor and
exporter versions, original capture and device IDs, capture hash and
clock bounds, permitted use, ground-truth event log, independent
reviewer, and join evidence. Attribute labels using reviewed source
events, verified benign workload logs, and clock alignment.
Leave ambiguous windows unknown and report them separately. Repeat
collection until each role meets the existing support and category
criteria. Require collector parity before combining sources.
Report capture-level recall and FPR with denominators, class and
category coverage, and any verified capture dependencies.
Document a negative result if the collected cohort fails these
conditions. Use its limits to guide collection instead of lowering
the gates.

Level 1 and its frozen model remain unchanged. The reserved
NF-CSE-CIC-IDS2018 benchmark stayed sealed. The flow files,
rule sidecars, publisher metadata and local audit outputs stay
outside Git.
