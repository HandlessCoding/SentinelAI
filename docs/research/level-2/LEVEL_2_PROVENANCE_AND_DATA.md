# G17 · Development data and capture provenance

## Decision

Use the **CNS 2022 corrected CIC-IDS2017 flow release** as the first
candidate for a separately approved acquisition and native-schema audit.
Its parent campaign differs from ToN-IoT, and its correction authors
publish both labeling decisions and exporter code. Within CIC-IDS2017,
try a capture-day boundary after verifying file membership, time zones,
coverage and exact-vector overlap. Keep LYCOS-IDS2017 as an alternate
export of the **same** CIC captures for auditing label and exporter
sensitivity. Any cross-environment experiment needs a common measurement
contract and a verified capture boundary.
[CIC correction project](https://intrusion-detection.distrinet-research.be/CNS2022/index.html) · [LYCOS paper](https://doi.org/10.1145/3486622.3493973)

G13 reserved the external benchmark. G14 established the exact
NF-ToN-IoT-v2 release and found no capture or session identifiers. In
G15, 64.82% of all rows still belonged to conflicting-label groups after
adding packet lengths and TCP flags. In G16, one tuple-linked component
contained 81.57% of the benign rows in the 250,000-row sample, and the
exploratory forest default FPR was 84.63% on a separate bounded draw
from the same release. These findings motivate obtaining better
development provenance and testing a compatible feature contract.
[G13 strategy](LEVEL_2_DATA_STRATEGY.md) · [G14 audit](LEVEL_2_DATA_AUDIT.md) · [G15 feature analysis](LEVEL_2_FEATURE_ENGINEERING.md) · [G16 experimental baseline](LEVEL_2_EXPERIMENTAL_BASELINE.md)

## ToN-IoT source capture and row mapping

UNSW collected original ToN-IoT traffic in its Canberra cyber range and
IoT labs. The network release includes packet captures and Zeek/Bro
logs and tables. The security-event ground truth includes timestamps.
UNSW describes original labeling by matching designated addresses and
event times. Keep any raw addresses, event times and exporter
identifiers as local audit or grouping metadata. UQ's comparison of
the original network tables reports 796,380 benign and 21,542,641
attack flows. Those totals describe the source network corpus before
NetFlow re-extraction. Time-aligned ground truth is useful for a new
extraction with traceable boundaries.
[UNSW release and ground truth](https://research.unsw.edu.au/projects/toniot-datasets) · [Original network dataset paper](https://doi.org/10.1016/j.scs.2021.102994) · [Original network counts in the UQ study](https://arxiv.org/html/2101.11315#S2)

UQ's v2 authors re-extracted flow records with nProbe. Their paper
describes matching endpoint addresses, ports and protocol to the
published attack events. The delivered v2 CSV contains elapsed
duration, with no absolute timestamp, parent packet-capture ID or
original Zeek flow ID. A repeated tuple can denote multiple distinct
sessions. Exporter timeouts, direction and boundaries can split or
combine different packets. The source documents reviewed provide no
verified row-level crosswalk or order guarantee. Matching by tuple,
CSV row number, duration or attack label would be ambiguous. The
source ground-truth files therefore cannot assign reliable capture or
session IDs to the current v2 rows by themselves.
[UQ v2 extraction and labeling](https://arxiv.org/html/2101.11315#S3.SS2)

A usable v2 crosswalk would bind the exact v2 CSV digest and row
identifier to an original capture ID and UTC interval. It would need
exporter configuration, an explicit policy for zero or multiple
matches, and reconciliation counts, including the unmatched rows.
The practical alternative is a separately approved timestamped
development release. UQ's v3 re-extraction has 27,520,260 flows
versus 16,940,496 in v2 and provides Unix-millisecond start and end
fields. UQ reports 16,792,214 benign and 10,728,046 attack flows
in v3. Its labeling method adds precise time to the tuple match.
Use v3 as a separate development input and verify capture grouping.
A time-block split in v3 would assess temporal transfer within ToN-IoT.
Assign earlier blocks to fitting and later blocks to calibration and
evaluation. Set boundaries before inspecting model scores and audit
flows or verified sessions that straddle those boundaries.
[UQ v3 record](https://doi.org/10.48610/44d7c5e) · [UQ release counts](https://staff.itee.uq.edu.au/marius/NIDS_datasets/) · [V3 fields and method](https://arxiv.org/html/2503.04404#S4)

UNSW's original release page permits academic research, requests
citation of its listed publications, and directs commercial users
to the author. The catalog DOI carries a GPL-3.0 rights field.
Confirm the terms for the particular original files with the publisher
before any redistribution or commercial use. The v2 and v3 UQ exports
have their own deposit records. Acquire only the relevant event
manifest, existing flow table or explicitly approved capture subset.
The original collection's exact packet archive size and the delivered
v3 archive size were unverified here.
[UNSW terms](https://research.unsw.edu.au/projects/toniot-datasets) · [Original catalog record](https://doi.org/10.26190/5d7ac9bfe8487) · [UQ v2 record](https://doi.org/10.48610/38a2d07) · [UQ v3 record](https://doi.org/10.48610/44d7c5e)

## CIC-IDS2017 alternatives

UNB describes five days of collection in one lab on July 3–7, 2017.
Monday contains benign traffic. The later days mix benign records
with scheduled attacks, including FTP/SSH brute force, DoS and DDoS,
web attacks, scanning, bot traffic, Heartbleed and infiltration in the
original collection. The day, hosts, schedule and labeling procedure
are possible shortcuts. The original release is available to
researchers with citation. The release page gives no general
redistribution terms for the derivative flow archives.
[UNB release and terms](https://www.unb.ca/cic/datasets/ids-2017.html) · [Original CIC paper](https://doi.org/10.5220/0006639801080116)

| Candidate | Capture and label evidence | Access and terms |
| --- | --- | --- |
| CNS 2022 corrected CIC-IDS2017 | Liu et al. rebuilt flows using a fixed CICFlowMeter and revised labels after checking the original traffic and inconsistent schedule documentation. Preserve raw labels for audit. Their guidance maps “Attempted” flows without observed malicious behavior to benign when in doubt. Freeze that primary policy and report a separate sensitivity analysis before model comparisons. Verify archive member coverage and counts by original day locally before assigning groups. | The authors' `CICIDS2017_improved.zip` returned **343,549,013 bytes** in its HTTP HEAD response (about **328 MiB** compressed). Allow **3–5 GiB** on D: for extraction and audit scratch. Check transfer size, member paths, headers and checksums before use. Cite the correction and original papers. A separate redistribution grant for the corrected archive was unverified. [Archive listing](https://intrusion-detection.distrinet-research.be/CNS2022/Datasets/) · [CIC-specific corrections](https://intrusion-detection.distrinet-research.be/CNS2022/CICIDS2017.html) · [Label policy](https://intrusion-detection.distrinet-research.be/CNS2022/Dataset_Download.html) |
| LYCOS-IDS2017 | Rosay et al. re-extracted the same CIC captures with LycoSTand and a different labeling method. Their Table 1 reports **1,837,500 flows**, including **1,395,659 benign** and **441,841 attack**. They dropped Thursday afternoon traffic, which leaves no infiltration support, and note uncertainty in web XSS labeling. Its altered flow boundaries and label coverage prevent treating it as a fixed row-by-row equivalent of the corrected CIC export. | The authors advertise CSV access for researchers and request citation. Their download index links to the repository's ZIP and TAR.GZ archives. Both archive HEAD requests timed out, leaving the exact bytes and packaged CSV inventory unverified. Check archive access, the revision, member names, sizes, hashes and terms before acquisition. The source-code availability does not establish a data redistribution license. [Author release](https://lycos-ids.univ-lemans.fr/) · [Download index](https://lycos-ids.univ-lemans.fr/download-lycos-ids2017.html) · [Methods and Table 1](https://www.scitepress.org/PublishedPapers/2022/107740/107740.pdf) |

The correction project lists other archives alongside the 2017 ZIP.
Any approved acquisition should select the named 2017 file only.
Check eligible class support in the delivered archive. Published counts
for the original release or the authors' earlier correction do not
substitute for counts from the chosen CNS 2022 file. If LYCOS is later
used for sensitivity analysis, compare native experiments on equivalent
documented capture days and report the coverage differences. Use
verified row linkage if comparing individual flows.
No new dataset was downloaded in G17, and the reserved
`NF-CSE-CIC-IDS2018-v2` campaign and its derivatives stayed outside
the work. [CNS 2022 paper](https://doi.org/10.1109/CNS56114.2022.9947235)

## Compatibility with flow-core-v1

Compatibility requires matching the unit and what the sensor counted.
The original Zeek logs, UQ nProbe exports, fixed CICFlowMeter and
LycoSTand use different flow boundaries or processing conventions.
Start with these checks before making a shared feature table.
[G15 exporter findings](LEVEL_2_FEATURE_ENGINEERING.md#feature-definitions-and-portability) · [nProbe definitions](https://www.ntop.org/guides/nprobe/flow_information_elements.html) · [Zeek connection fields](https://docs.zeek.org/en/current/scripts/base/protocols/conn/main.zeek.html#type-Conn::Info)

| Measurement | Compatibility assessment |
| --- | --- |
| Protocol and direction | IP protocol number is a plausible shared field after verifying supported protocol codes. CICFlowMeter's forward and reverse directions follow the flow's first observed packet. nProbe exposes its source/destination orientation and Zeek can revise originator assignment. Check direction with matched two-way, reverse-first and incomplete-flow fixtures. LycoSTand's different flow construction needs its own direction and boundary checks. |
| Duration | Fixed CICFlowMeter uses packet timestamps in microseconds. The G14 core stores exported milliseconds, and Zeek's seconds can omit trailing TCP traffic. A conversion to milliseconds needs a fixed rounding rule **and** matched flow start/end semantics. Preserve the native values pending those checks. Confirm LycoSTand's timestamp and duration units against the exact export header and code before converting. |
| Directional packet counts | These are candidate shared counters once direction, retransmission and sampling treatment, fragmentation, termination, and active/idle timeouts agree. LycoSTand's revised termination behavior can yield different counts for flows derived from the same traffic. |
| Directional bytes | Fixed CICFlowMeter sums transport payload bytes. nProbe's mapped IPFIX octet field is defined using IP headers and payload, though G14 observed values as low as four exported bytes with a forward packet. Zeek separates payload bytes and IP bytes. Keep native counters separate until matched-packet accounting is verified. Confirm LycoSTand byte semantics for the chosen columns before any mapping. |
| TCP flags | nProbe exports cumulative whole-flow and directional masks, while CICFlowMeter exposes flag counts and selected directional counts. Whole-flow counts can show that a flag occurred, but do not recover all directional masks. Zeek's stock history is lossy. LycoSTand flag counters require a verified directional mapping. Omit these from a shared contract until the measurements agree. |

The implemented adapter validates the fixed CICFlowMeter source header
names for protocol, microsecond duration, packet counts and payload
octets. It returns a native typed record. It does not infer timestamps,
flags or labels, or construct a `flow-core-v1` vector. A separate v3
timestamp adapter reads Unix milliseconds and validates interval
ordering. Both were tested with synthetic records. The actual released
CIC headers and LYCOS mappings remain an acquisition-time check.
[Fixed header definitions](https://github.com/GintsEngelen/CICFlowMeter/blob/master/src/main/java/cic/cs/unb/ca/jnetpcap/FlowFeature.java) · [Fixed packet timestamps](https://github.com/GintsEngelen/CICFlowMeter/blob/master/src/main/java/cic/cs/unb/ca/jnetpcap/PacketReader.java) · [Fixed byte and counter implementation](https://github.com/GintsEngelen/CICFlowMeter/blob/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java) · [Adapter and metadata checks](../../../ml/level2_provenance.py)

## Capture-aware split and next experiment

1. **Audit the corrected 2017 export after approval.** Record the original
   capture ID, release file digest and exporter version, source evidence,
   UTC start and end, and eligible benign and attack counts per block.
   Preserve local session IDs or derive timestamped tuple sessions only
   with independently verified timeout and boundary rules. A CSV
   filename or a corrected label alone cannot establish a session.
2. **Preregister a native-schema pilot.** Test a chronological plan with
   July 4–5 for fitting, July 6 for calibration and July 7 for a locked
   within-campaign validation fold. Hold July 3 separately as an
   FPR-only benign check. This is a candidate assignment, conditional on
   the audited time zones, class support and linkage. Report category
   support by day, including attacks absent from fit or calibration.
   Apply the G15 exact-vector and verified session grouping to the
   selected predictor tuples. Reject the proposed boundary if a
   connected group crosses it or class coverage is inadequate. Do not
   repair it by moving future flows or using validation outcomes to
   choose another day.
3. **Use fixed, bounded comparisons.** After the audit and split pass,
   fit a majority-class reference, Logistic Regression and a small
   Random Forest from G16 on one source-native, documented schema.
   Compare fixed configurations on the same approved folds. Keep IPs,
   raw ports, capture IDs, timestamps, labels, attack names and
   attempted-label markers out of predictors. Select thresholds on
   calibration captures only. Report confusion counts, ROC AUC and
   average precision, FPR, attack recall, eligibility and rejected-row
   counts per capture. Use G13's proposed **≤10% FPR and ≥95% recall**
   as an experimental target. The 5% FPR goal remains exploratory.
4. **Test cross-environment transfer separately.** Obtain a verified
   ToN-IoT time-block release or another permitted development
   campaign with both classes. Use an identical exporter contract and
   document processing, or restrict the experiment to a verified
   compatible subset such as protocol, duration and directional
   packet counts after parity. If parity cannot be established,
   keep native experiments separate. Check capture lineage, session and
   exact-vector overlap independently. Reserve a whole documented
   campaign for a fresh transfer test and freeze decisions before
   scoring. The final reserved benchmark stays sealed.

The new `check_capture_boundary` function checks declared lineage, original
capture IDs and optional original capture hashes, nonoverlapping
same-lineage time bounds across the boundary, chronological ordering when requested, and
minimum class denominators. Corrected CIC and LYCOS aliases resolve
to one lineage. A caller must verify the underlying evidence. Use
the [G15 split planner](../../../ml/level2_splits.py) afterward to enforce
exact-vector and session boundaries. A benign-only block can exercise
FPR with attack recall left undefined.

```powershell
& .\.venv\Scripts\python.exe -B -m unittest discover -s tests -p 'test_level2_provenance.py' -v
```

All **126 Python tests** and **22 frontend tests** passed, along with the
frontend production build. The Level 1 artifact matched its recorded
checksum. G17 generated no fitted models.
