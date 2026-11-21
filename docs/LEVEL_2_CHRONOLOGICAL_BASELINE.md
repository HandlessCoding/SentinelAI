# G19 · Chronological validation and baseline feasibility

## Protocol and feasibility criteria

Use the corrected CIC-IDS2017 release verified in G18. Keep the
Tuesday and Wednesday capture days for fitting, Thursday for
calibration, and Friday for one within-campaign validation. Monday
is a benign-only diagnostic outside the primary partitions. Validate
member dates, the exported timestamps, and the end time derived
from each flow's duration. Keep the export's clock convention and
CSV record numbers. The files share one capture campaign.
[G13 targets](LEVEL_2_DATA_STRATEGY.md) · [G14 audit](LEVEL_2_DATA_AUDIT.md) · [G15 analysis](LEVEL_2_FEATURE_ENGINEERING.md) · [G16 pilot](LEVEL_2_EXPERIMENTAL_BASELINE.md) · [G17 provenance](LEVEL_2_PROVENANCE_AND_DATA.md) · [G18 audit](LEVEL_2_CIC_AUDIT.md)

| Feature candidate | Exact grouping fields |
| --- | --- |
| Native CIC counters | Protocol, flow duration in microseconds, forward and reverse packet counts, forward and reverse payload byte counts |
| Portable subset candidate | Protocol, flow duration in microseconds, forward and reverse packet counts |

Both candidates use typed native CIC values. The portable subset
uses concepts available across flow tools. Collector timeout,
direction, packet inclusion, and duration semantics still need
matched-capture verification before model transfer. Removing
payload bytes also tests sensitivity to the corrected dataset's
label rules, some of which use forward payload length. Exclude
IP addresses, ports, flow IDs, timestamps, capture and row IDs,
labels, attempted markers, and suspect or unverified rate, header,
and other exporter-specific fields from both predictor sets.
[Correction authors' label rules](https://intrusion-detection.distrinet-research.be/CNS2022/CICIDS2017.html) · [Zeek connection field definitions](https://docs.zeek.org/en/current/scripts/base/protocols/conn/main.zeek.html#type-Conn::Info)

The primary rule keeps the fit cohort intact, excludes Thursday
rows with any key seen in fit, then excludes Friday rows with any
key seen in fit or **retained** Thursday. The keys are both typed
predictor vectors, the direction-independent exported five-tuple,
and the literal exported flow ID. No verified session ID is available.
Tuples and flow IDs provide a conservative proxy that can group
unrelated connections and miss sessions whose keys change. A new
row is excluded using only its keys and its temporal role. Binary
labels and raw categories are used solely to audit support under
G18's declared treatment of attempted flows. Check the unfiltered
split and compare native-vector-only, both-vector-only, and
all-keys filtering against the complete earlier source blocks to
quantify the cost of each control. Retain the original archive.

Set these gates before computing retained support:

1. The archive must match the G18 SHA-256. Its CRCs, native predictor
   fields, grouping fields, and calibration/validation chronology
   must validate.
2. The retained primary partitions must have zero overlap for
   every key across all three pairs of roles.
3. Each primary partition must retain at least 10,000 benign and
   10,000 attack records and at least half of each original binary
   class. Retain at least half of each attack category that has
   100 or more source records in the partition. Report support for
   rarer categories with no gate. The count floor protects the
   pooled denominators. The retention floors check whether exclusions
   leave evaluation dependent on a narrow subset of a scheduled
   attack or benign population. They do not establish representativeness.

Compare both candidates on the same retained cohorts only if every
gate passes. Use a fixed seed, at most 120,000 group-complete fit
rows, regularized Logistic Regression with fit-only preprocessing,
and a single-worker Random Forest with 24 trees, depth at most 10,
at most 256 leaves per tree, and at least 20 rows per leaf. Use 0.5
as the default cutoff. Select any exploratory 5% or 10% FPR operating
point on Thursday only, and score the fixed cutoffs on Friday.

## Audit and manifest

The runner reads the five CSVs directly from the approved ZIP on
D:. It validates the digest and CRCs, checks required numeric
counters and grouping fields, and sorts exact keys in bounded
24 MiB estimated chunks per key. Exact matches use the entire
encoded key. A compact row index supports a second pass over
groups to verify the retained boundaries. The runner keeps
scratch files beside the archive and requires 2 GiB of free disk
space. It uses only the Python standard library.
[Audit runner](../ml/cic_chronological_split.py) · [Synthetic tests](../tests/test_cic_chronological_split.py)

```powershell
& .\.venv\Scripts\python.exe -B -m ml.cic_chronological_split
if ($LASTEXITCODE -ne 0) { throw 'Chronological split audit failed.' }
& .\.venv\Scripts\python.exe -B -m unittest discover -s tests -v
```

The two local manifest files are under
`data/level2/cicids2017-improved/` and ignored by Git.

- `g19-split-manifest.json` contains the archive SHA-256, capture
  roles and timestamp bounds, feature schemas, overlap counts,
  eligibility rules, class and category support, and training gate
  outcome. It also records the row manifest SHA-256.
- `g19-eligible-rows.csv.gz` records the CSV member, one-based data
  record number, partition, and overlap flags. The mask values are
  1 for the native vector, 2 for the portable vector, 4 for the
  direction-independent tuple, and 8 for the exported flow ID. A
  development row's bits indicate matches with earlier source or
  earlier retained blocks, respectively. Monday's bits describe
  overlap with the unfiltered development blocks. The row manifest
  contains eligibility decisions and omits predictor values,
  addresses, and labels. Check `training_allowed` in the JSON
  before using any row flag for training.

## Measured results

**Phase 1 failed the coverage gates.** The audit read all 2,099,976
records in about 4 minutes and 10 seconds. The archive digest and
five member CRCs verified, and each day's first start followed the
preceding day's latest duration-derived end. The selected numeric
fields and key inputs passed validation for every row. The native
fields still include five zero-duration records, 33 zero counts in
the forward direction, and 1,510 protocol-zero records. These
observations remain in the audit. G18 found nonfinite rates and
negative header lengths in fields outside both predictor contracts.
[G18 value quality and clock checks](LEVEL_2_CIC_AUDIT.md#value-quality-and-clock-checks)

### Group isolation

| Boundary | Shared native vectors | Shared portable vectors | Shared bidirectional tuples | Shared flow IDs |
| --- | ---: | ---: | ---: | ---: |
| Unfiltered fit → calibration | 20,523 | 29,926 | 57,967 | 57,945 |
| Unfiltered fit → validation | 20,812 | 29,780 | 69,183 | 68,974 |
| Unfiltered calibration → validation | 14,579 | 22,202 | 39,683 | 39,645 |
| Primary fit → calibration | 0 | 0 | 0 | 0 |
| Primary fit → validation | 0 | 0 | 0 | 0 |
| Primary calibration → validation | 0 | 0 | 0 | 0 |

The primary union removed 222,593 Thursday rows and 370,654 Friday
rows. On Friday, 303,950 rows matched on a portable vector and
168,909 matched on a tuple. Matches on multiple keys affected
305,925 Friday rows, so adding the per-key counts would overstate
the number of exclusions. The retained history rule kept an extra
1,983 Friday rows relative to the more conservative all-source rule.
All 1,983 were benign under the declared policy.

Both-vector filtering alone left 26,126 shared tuples and 25,927
shared flow IDs between fit and Friday. Monday is benign-only.
Of its 371,624 records, 219,526 (59.07%) match at least one key in
the unfiltered development roles. It remains outside the main
protocol. The measured time separation establishes chronology.
It cannot verify session independence within the capture campaign.

### Retained support

Fit kept all 818,719 source records under every policy, including
640,141 benign and 178,578 attack records (21.81% attack).

| Policy | Thursday benign | Thursday attack | Friday benign | Friday attack |
| --- | ---: | ---: | ---: | ---: |
| Unfiltered | 290,169 | 71,907 | 292,611 | 254,946 |
| Native vector only | 237,301 | 55,113 | 230,221 | 97,819 |
| Both vectors only | 152,222 | 26,971 | 142,856 | 97,219 |
| All keys against earlier source | 112,616 | 26,867 | 107,124 | 67,796 |
| **Primary, all keys against retained history** | **112,616** | **26,867** | **109,107** | **67,796** |

The primary calibration set contains 139,483 records, 19.26% attack.
It retained 38.81% of the source benign rows and 37.36% of the
source attacks. The primary validation set contains 176,903 records,
38.32% attack, down from 46.56% in the source. It retained 37.29%
of the source benign rows and 26.59% of the source attacks.
Each class passed the absolute 10,000-row floor. Both classes
missed the 50% retention floor on both days. Even the
native-vector-only policy against the earlier source days kept
only 38.37% of Friday attacks.

| Role | Attack category | Source rows | Primary retained | Retained |
| --- | --- | ---: | ---: | ---: |
| Calibration | Infiltration - Portscan | 71,767 | 26,831 | 37.39% |
| Calibration | Infiltration | 36 | 36 | 100.00% |
| Calibration | Web Attack - Brute Force | 73 | 0 | 0.00% |
| Calibration | Web Attack - XSS | 18 | 0 | 0.00% |
| Calibration | Web Attack - SQL Injection | 13 | 0 | 0.00% |
| Validation | Botnet | 736 | 733 | 99.59% |
| Validation | DDoS | 95,144 | 65,982 | 69.35% |
| Validation | Portscan | 159,066 | 1,081 | 0.68% |

Two categories missed the gate for categories with at least
100 source rows. Three additional rare categories disappeared
from calibration. The label-free rule still changed the evaluation
population substantially. Portscan made up 62.39% of Friday's
source attacks and 1.59% of retained attacks. DDoS rose from
37.32% to 97.32%. The campaign schedule itself is a confounder.
None of the exact Friday attack labels occurred on fit or
calibration days. Fit category counts remain as published in
the G18 audit, under the same label policy.
[G18 label coverage](LEVEL_2_CIC_AUDIT.md#label-coverage)

## Decision

The manifest sets `training_allowed` to `false`. Phase 2 did
not run. There are no fitted models, selected thresholds, or
new performance metrics. Allowing key overlap or lowering the
retention gates after seeing this result would change the
evaluation protocol. A future protocol should start with
separately documented development captures that include benign
traffic and meaningful support across attack categories. Verify
the capture and session identifiers and run collector parity
checks before choosing a common predictor contract. Keep the
independent NF-CSE-CIC-IDS2018 benchmark reserved for final
evaluation.

The full Python suite passed 136 tests, including five new
synthetic tests. All 22 frontend tests and the production build
passed. The frozen Level 1 pipeline matches its recorded
SHA-256. Level 1 remains unchanged, and the reserved benchmark
stayed sealed.
