# Controlled capture lab

The Level 2 lab records owned, authorized traffic and extracts Zeek-native
features. It operates separately from the Level 1 API, dashboard, and frozen
UNSW-NB15 pipeline. G26 verified the sensor, and G27 verified four bounded
benign captures on the same VM pair.
[Provisioning record](research/lab/LEVEL_2_G26_ZEEK_VERIFICATION.md) ·
[Collection results](research/lab/LEVEL_2_G27_BENIGN_COLLECTION.md)

## Provision isolated guests

1. Use VirtualBox and two Linux guests. G26 verified two Ubuntu 24.04.5 LTS
   guests, each with one vCPU, 2 GiB RAM, and a 10 GiB dynamically allocated
   disk. Put VM disks, snapshots, local settings, and captures under the
   ignored `data/level2/capture-lab/` tree on D:. Verify a downloaded Ubuntu
   appliance against Canonical's signed checksum manifest before import.
   [Ubuntu cloud images](https://cloud-images.ubuntu.com/releases/noble/release/) ·
   [Canonical checksum verification](https://ubuntu.com/docs/public-images/public-images-how-to/verify-image-checksum/)
2. Cloud images use NoCloud media with a `CIDATA` volume and guest-specific
   `meta-data`, `user-data`, and `network-config`. Assign unique instance
   IDs and use locally generated console credentials. Check the imported
   adapter settings while powered off. Install Zeek and tcpdump in the
   sensor using the distribution packages from supported sources. Obtain
   separate authorization for temporary Internet access or infrastructure
   changes. G26 verified Zeek 8.0.11 and tcpdump 4.99.4.
   [Canonical VirtualBox import](https://ubuntu.com/docs/public-images/public-images-how-to/run-an-ova-using-virtualbox/) ·
   [Supported Zeek packages](https://docs.zeek.org/en/current/install.html)
3. With both guests off, attach their sole enabled adapter to a dedicated
   **Internal Network**, called `sentinelai-g26-intnet` in the verified lab.
   Disable other adapters and keep shared folders and clipboard integration
   disabled for collection. Use `lab0` on each guest with static addresses
   `10.75.26.10/24` for the sensor and `10.75.26.20/24` for the client.
   The collector uses these fixed endpoints to confine transactions to that
   lab. Configure neither a gateway nor IP forwarding.
   [VirtualBox network modes](https://docs.oracle.com/en/virtualization/virtualbox/7.2/user/networkingdetails.html)
4. Verify the powered-off adapter settings and the live addresses and
   routes. Check for external routes to the host, LAN gateway, and
   representative Internet addresses using route lookups. Check two-way
   peer reachability inside the lab and retain the evidence locally.
   Stop before collection if an unexpected adapter or route is present.
   Shut down cleanly and take a baseline snapshot.

## Verify the sensor offline

From a copy of the tracked source on the Linux sensor:

```bash
SENTINELAI_ZEEK_BINARY=/opt/zeek/bin/zeek python3 -B -m unittest discover -s tests -p test_lab_zeek_integration.py -k synthetic -v
python3 -B -m ml.lab_demo --root /path/to/new-demo --zeek-binary /opt/zeek/bin/zeek
```

The offline runner keeps the source PCAP intact and records the Zeek version,
processing settings, and artifact SHA-256 values. Use `ml.lab_capture zeek`
to process an existing authorized PCAP. The G26 synthetic test
checks three UDP flows and their directional counts and duration. Packet
and IP octet counts are separate from payload byte estimates. Zeek can omit
service and duration. Extraction keeps those values missing and records
validation issues. The Zeek fields have a different contract from UNSW-NB15
and CICFlowMeter. [Zeek connection schema](https://docs.zeek.org/en/v8.0.11/scripts/base/protocols/conn/main.zeek.html#type-Conn::Info)

## Record a bounded benign batch

Copy the tracked source and the [pilot plan](../examples/lab_benign_pilot.json)
to both guests. Create a private `routes.json` with `host`, `lan_gateway`,
`internet_ipv4`, and `internet_ipv6` mapped to representative addresses
outside the lab subnet. The script performs local route lookups without
transmitting packets to those addresses.

```bash
sudo python3 -B -m ml.lab_benign sensor plan.json routes.json /var/tmp/sentinelai-sensor
sudo python3 -B -m ml.lab_benign client plan.json routes.json /var/tmp/sentinelai-client
```

Start the sensor first. Wait for `G27_SENSOR_READY`, then run the client in
the other guest. Both use the same plan. Each capture has a unique ID,
original session ID, and seed. The sensor starts recording only after the
client verifies its own network. Use a fresh output directory for every
attempt. The captures contain only the approved HTTP and UDP service traffic.
The local coordinator stays outside the capture filter.

Copy original PCAPs, Zeek logs and receipts, and the independent application
logs to the ignored lab root by an authorized offline handoff. The serial
importer accepts a [framed console archive](research/lab/LEVEL_2_G27_BENIGN_COLLECTION.md#reproduce-a-bounded-batch)
from each guest. Then run the evidence and capture audit:

```powershell
$lab = 'data/level2/capture-lab/g27'
& .\.venv\Scripts\python.exe -B -m ml.lab_benign_audit $lab "$lab/pilot-check.json" examples/lab_benign_pilot.json
```

Use a fresh report filename and keep the local permission record at
`evidence/g27-authorization.json`. Expand only after the pilot passes
isolation, evidence, and packet accounting. The
[expansion plan](../examples/lab_benign_expansion.json) specifies three more
bounded sessions. Pass both plans to the audit to compare the whole cohort.

## Register and review evidence

Use capture and session IDs for the original recording boundaries, with
stable device, environment, and observation-point IDs. Review the scenario,
client and service logs, and time intervals before attributing a label.
Endpoints and ports can join recorded events to flows. They never determine
the label on their own. Flows with incomplete or ambiguous evidence remain
`unknown`. One unverified connection keeps the G27 capture window unknown.

New manifests can list the review, original client and service logs, and
recorder diagnostics as relative `evidence_files`. The registry verifies their
checksums directly, even if a capture has no reviewed label window. Prior
manifests retain their original pins. The G27 re-audit separately compares
the original event and recorder files with the hashes in its review.
See the [capture draft example](research/lab/LEVEL_2_CONTROLLED_CAPTURE_LAB.md#local-workflow)
for the remaining manifest fields.

```powershell
& .\.venv\Scripts\python.exe -B -m ml.lab_capture --root $lab records g27-pilot-02
& .\.venv\Scripts\python.exe -B -m ml.lab_capture --root $lab audit g27-pilot-02
```

The G27 audit matches independent application evidence, packet totals, and
feature values. It reports invalid or missing fields, duplicate captures,
and repeated vectors without removing data. Independent validation also
requires separate device and capture lineage, sufficient reviewed class
coverage, and evidence that the feature contract transfers across
environments. G27's four recordings share one device pair and environment.
[Prespecified feasibility gates](research/level-2/LEVEL_2_CAPTURE_DATA_STRATEGY.md#feasibility-gates-before-fitting)

## Matched control and label validation

G29 repeats the frozen G27 pilot workload with fresh capture and session
IDs and the same seed, traffic services, and observation point. Preflight
checks the powered-off adapter configuration before each run. Both guests
then check their live routes before the client starts the capture handoff.
Compare the client and service evidence, packet accounting, and feature
coverage before expanding the recording plan. [G27 pilot plan](../examples/lab_benign_pilot.json)

`g29-control-01` produced three reviewed benign flows from five transactions.
Two flows used TCP and one used UDP. Zeek 8.0.11 accounted for all 34 packets
in the 5,025-byte capture, with zero kernel drops and zero invalid feature
values. Only the UDP `service` field was missing. There were no unknown or
positive flows in the control. All three core and rich vectors were distinct
within the capture. Two core vectors and zero rich vectors matched the G27
pilot. No PCAP or Zeek-log checksum matched the existing G27 registry. The
new session shares G27's device pair, physical host, and observation point.
Offline audit details and checksummed evidence are kept under the ignored
`data/level2/capture-lab/g29/` directory.

Use `ml.lab_demo` on an isolated sensor to validate `benign`, `attack`, and
`unknown` handling and exact-vector conflict reporting offline. The
`attack` fixture is a test annotation on ordinary synthetic UDP packets.
The G29 fixture produced one row per label and one shared key across all
three rows. Synthetic captures are excluded from real cohort coverage and
predictor export.

**G29 live attack collection is BLOCKED.** The registry contains one real session, the
matched benign control. There is no real capture of reconnaissance or
unsuccessful authentication to validate, so a benign-versus-attack comparison
and pilot expansion are pending.

For offline verification of an authorized positive recording, retain the
original PCAP, capture provenance, recorded client actions, service-side
observations, UTC bounds, and an independent review. The reviewer must match
the action and outcome to the packet evidence for every flow in a labeled
window. Keep the window `unknown` when the evidence is incomplete or cannot
rule out unrelated flows. Process the PCAP with the same offline Zeek settings
and apply the existing capture quality and overlap checks before expanding.

For reviewed real captures, `ml.lab_capture predictors` emits five explicit
feature columns from eligible flows. It emits the transport protocol and
directional IP byte and packet counts. `records` includes label, timestamp,
capture ID, source, and review details for audit work. Keep identity and
scenario information in the registry, and keep labels separate from
predictors. The export does not assign roles or certify a training cohort.

## Triage recorded flows in SentinelAI

G30 imports a verified Zeek JSON `conn.log` into the offline **Network
Traffic** dashboard. Two versioned rules flag TCP `S0` (no response observed)
and `REJ` (connection rejected). Service downtime, filtering, or incomplete
visibility can produce the same states. A rule finding prompts review.
The independently reviewed capture label stays separate, as do the Level 1
model's suspected-attack alerts. The importer collects no traffic.
[Offline import and API](DATABASE_SETUP.md#import-reviewed-zeek-flows-offline) ·
[Zeek state definitions](https://docs.zeek.org/en/v8.0.11/scripts/base/protocols/conn/main.zeek.html#type-Conn::Info)

## Audit rule findings against reviewed labels

The read-only audit reruns the two versioned rules on explicitly named,
checksum-verified captures. It scores reviewed TCP flows with a recognized
Zeek state. Unknown labels, reviewed rows outside rule scope, and synthetic
fixtures receive separate coverage counts. The report uses JSON `null` for
precision without findings, recall without reviewed positives, and
false-positive rate without reviewed negatives. The same capture contributes
to every participating device's coverage, so device totals overlap.

```powershell
$g27 = 'data/level2/capture-lab/g27'
$g29 = 'data/level2/capture-lab/g29'
& .\.venv\Scripts\python.exe -B -m ml.evaluate_zeek_rules `
  --capture $g27 g27-pilot-02 --capture $g27 g27-expand-02 `
  --capture $g27 g27-expand-03 --capture $g27 g27-expand-04 `
  --capture $g29 g29-control-01
```

The G31 audit reverified 15 original client, service, and recorder files.
It evaluated five sessions from the same two guests and one observation
point.

| Capture | Reviewed benign | Eligible TCP | Excluded UDP | Findings |
| --- | ---: | ---: | ---: | ---: |
| `g27-pilot-02` | 3 | 2 | 1 | 0 |
| `g27-expand-02` | 4 | 3 | 1 | 0 |
| `g27-expand-03` | 5 | 3 | 2 | 0 |
| `g27-expand-04` | 4 | 3 | 1 | 0 |
| `g29-control-01` | 3 | 2 | 1 | 0 |

Overall, TP, FP, and FN were zero and TN was 13. The observed false-positive
proportion was 0/13 on this control sample. Precision, recall, and
positive-class evaluation were unavailable. The cohort contained no reviewed
attacks, unknown labels, or synthetic rows. Five sessions from one lab leave
general false-alarm rates and cross-environment performance unmeasured.
G28 remains deferred, and G29 live attack collection remains blocked.

## Qualify the Zeek-native feature contract

### UNSW-NB15 exporter assessment

The UNSW release documents features and publishes packet traces, exported
Argus and Bro records, and prepared tables. The original paper describes
joining Argus records with Bro connection, HTTP, and FTP logs. Chapter 3
of the author's thesis gives example extraction commands and pseudocode
for the 12 additional features. The paper describes a SQL Server join and
the thesis describes MySQL. The reviewed sources did not establish a
versioned runnable reference for the prepared 42-column model input,
including the original Argus/Bro versions and settings, exact joins,
flow timeout and direction rules, and reference rows tied to a trace.
The generic Argus client is documented. Its output alone cannot establish
equivalence to that prepared table.
[UNSW release](https://research.unsw.edu.au/projects/unsw-nb15-dataset) ·
[Paper](https://doi.org/10.1109/MilCIS.2015.7348942) ·
[Author thesis, chapter 3](https://www.researchgate.net/publication/328784548_Designing_an_online_and_reliable_statistical_anomaly_detection_framework_for_dealing_with_large_high-speed_network_traffic) ·
[Argus client manual](https://qosient.com/argus/man/man1/ra.1.pdf)

| Status | UNSW predictors and evidence |
| --- | --- |
| First parity candidates | `proto`, `dur`, `spkts`, `dpkts`, `sbytes`, and `dbytes` have comparable concepts. Argus documents directional packet counts and transaction bytes. Zeek records IP octets and application payload estimates separately. TCP/UDP tokens can be compared on matched flows. Source/originator direction, segmentation, duration boundaries, byte basis, and treatment of incomplete flows remain unverified. |
| Defined relationship, pending operand parity | `is_sm_ips_ports` tests both equal addresses and equal ports. Its Boolean logic is reproducible on known comparable endpoints. The released flow identities and missing or non-port encodings still need a reference check. Endpoint-derived features are outside `zeek-flow-v1`. |
| Ambiguous or dependent on unverified semantics | `state`, `service`, `rate`, `sload`, `dload`, `smean`, `dmean` depend on exporter vocabulary, flow segmentation, time base, byte basis or packet-size averaging. The Argus client documents packet rate in packets/s and load in bits/s. Those definitions alone cannot validate the prepared values. |
| Unsupported by existing connection observations | `sttl`, `dttl`, `sloss`, `dloss`, `sinpkt`, `dinpkt`, `sjit`, `djit`, `swin`, `dwin`, `stcpb`, `dtcpb`, `tcprtt`, `synack`, `ackdat` require packet-level observations and exporter rules. Argus documents inter-arrival and jitter in milliseconds. Zeek's missing-byte count cannot supply retransmitted or dropped packet counts. |
| Unsupported by the current import | `trans_depth`, `response_body_len`, `is_ftp_login`, `ct_ftp_cmd`, `ct_flw_http_mthd` require HTTP/FTP transaction extraction and alignment. `ct_state_ttl` uses designated state/TTL combinations. `ct_srv_src`, `ct_srv_dst`, `ct_dst_ltm`, `ct_src_ltm`, `ct_src_dport_ltm`, `ct_dst_sport_ltm`, `ct_dst_src_ltm` use 100 connections ordered by last time. Reproduction needs the original ordering, tie handling, window resets and warm-up, and prepared-table encoding. |

Same-PCAP UNSW parity was unavailable. Zero of 42 fields are verified
end to end, and no fields were scored for pass/fail. If a trustworthy
reference becomes available, freeze the benign PCAP digest and exporter
versions/settings first. Prespecify a one-to-one match on transport and
endpoints, start-time tolerance from timestamp resolution, and a duration
tolerance from each exporter's documented precision. Record direction
swaps and assess unmatched or ambiguous flows. Compare integers and
protocol tokens exactly after alignment. Report absent values separately
from zeros, and publish both matched-flow coverage and per-field results.
[G33 qualification matrix](research/level-2/LEVEL_2_EXPERIMENTAL_BASELINE.md#unsw-to-zeek-feature-compatibility)

### `zeek-flow-v1`

One vector represents one bidirectional Zeek `conn.log` record from one
original capture. Zeek determines flow start, grouping, and termination.
The projection never joins rows across capture boundaries or reassigns
direction. `orig` and `resp` refer to Zeek's originator and responder,
which can be uncertain on partial captures. The checksummed audit requires
Zeek 8.0.11 receipts with JSON output and the connection size analyzer
enabled. [Zeek 8.0.11 field reference](https://docs.zeek.org/en/v8.0.11/scripts/base/protocols/conn/main.zeek.html#type-Conn::Info)

| Ordered predictors | Type and meaning |
| --- | --- |
| `proto` | Required categorical string. This contract supports `tcp` and `udp`. |
| `orig_pkts`, `resp_pkts` | Required nonnegative integers. Observed packet counts in each Zeek direction. |
| `orig_ip_bytes`, `resp_ip_bytes` | Required nonnegative integers. IP-level octets summed from the observed packets in each direction, including IP headers. |
| `duration_ns` | Nullable nonnegative integer nanoseconds. Uses the parsed Zeek duration in seconds, with supported fractional nanoseconds rounded up. Zeek's duration excludes trailing TCP packets that add no new payload after a direction closes. |
| `conn_state` | Nullable categorical string in Zeek's documented state vocabulary. It describes observed connection behavior. |

Zero is a measured value. Optional absence is JSON `null`. Missing
required, malformed, out-of-range, or unsupported values make a row
ineligible and are counted by feature. Integer values must fit the
offline store's signed 64-bit range. The projection fits no preprocessing
and uses no missing-value imputation. IP addresses, ports, flow IDs and
timestamps, device/session/capture identifiers, scenario and evidence
metadata, labels, and rule outputs stay outside the vector. Service,
history, and payload or missed bytes remain available for diagnostics
through existing flow observations.
[Contract and audit implementation](../ml/zeek_flow_v1.py)

Run a read-only cohort audit from the repository root. It verifies the
capture, log, receipt, and evidence hashes, limits input to 16 captures
with 64 MiB per PCAP or log and 10,000 records per log, and emits aggregate
coverage. Duplicate capture IDs or PCAP/log hashes are rejected. Exact
predictor vectors, including repeated ones, are retained and counted,
with cross-capture matches and reviewed label conflicts reported.
Unknown labels remain unknown. Synthetic captures are excluded.

```powershell
$lab = 'data/level2/capture-lab'
& .\.venv\Scripts\python.exe -B -m ml.zeek_flow_v1 `
  --capture "$lab/g26" g26-benign-01-reviewed `
  --capture "$lab/g27" g27-pilot-02 --capture "$lab/g27" g27-expand-02 `
  --capture "$lab/g27" g27-expand-03 --capture "$lab/g27" g27-expand-04 `
  --capture "$lab/g29" g29-control-01
```

| Verified cohort | Reviewed benign | TCP | UDP | All seven fields present |
| --- | ---: | ---: | ---: | ---: |
| G26, one reviewed capture | 1 | 1 | 0 | 1 |
| G27, four captures | 16 | 11 | 5 | 16 |
| G29, one matched control | 3 | 2 | 1 | 3 |
| Total | 20 | 14 | 6 | 20 |

Extraction matched the offline import projection on all 20 rows.
There were 20 distinct vectors, zero cross-capture matches, zero label
conflicts, and zero directional zero/nonzero packet and byte mismatches.
The older five-field projection had two repeated groups affecting four
rows. The audit rejected the unreviewed G26 alias by PCAP/log checksum
when it was supplied alongside the reviewed capture. Every observed
connection state was `SF`. This narrow benign sample leaves incomplete
and other connection states unverified on real data. Service was missing
on six rows and is outside the predictor set. Six sessions used
one observation point, the same two devices, and one environment.
There were zero reviewed attacks or unknowns in the admitted cohort.
The results establish extraction consistency on these recordings.

### G35 data gate

Use `zeek-flow-v1` for the next network-flow model once data qualifies.
HGB-34 Full and HGB-35 No TTL retain their frozen UNSW qualification
roles and remain separate from the Zeek research path. Level 1 stays
active. The G32 holdouts, official UNSW test rows, and reserved 2018
benchmark stay sealed.

The next concrete experiment is an **offline export and provenance
pilot**. Request an already-recorded, authorized set of original
captures from a second environment, with routine benign and independently
verified attack windows collected under comparable conditions. Require
original capture, device and sensor identities, UTC bounds, the
checksummed Zeek export and settings, and time-aligned review evidence.
The source owner can run the pinned exporter locally and share reviewed
flow logs and provenance if packet sharing is restricted. Keep the existing
G26/G27/G29 data as extraction controls.

Before fitting, obtain distinct eligible cohorts for fitting, calibration,
model comparison, and final development validation. Apply the existing
coverage gate of at least 1,000 eligible flows per class per role, with
reviewed benign coverage and at least two original positive runs in final
validation. Reserve the independently instrumented environment for the
sealed validation role, check related recordings and copied traffic
across all roles, and audit overlaps and category support. Retain
independently recorded repeated vectors and report a separate
known-vector versus novel-vector analysis. Preflight uses coverage
aggregates for validation, with detailed rows and labels sealed until
the model and policy are fixed.
[Coverage and provenance gates](research/level-2/LEVEL_2_CAPTURE_DATA_STRATEGY.md#feasibility-gates-before-fitting)

No qualifying independent source is currently registered. The IoT-23
Kaggle derivative lacks resolved capture and review provenance, and
earlier official flow-only checks did not establish eligible cohorts.
G28 remains deferred and G29 live attack collection remains blocked.
Owner authorization and evidence availability govern the G35 pilot.
[Archive audit](research/level-2/LEVEL_2_IOT23_CAPTURE_RECONCILIATION.md) ·
[Official flow-source feasibility](research/level-2/LEVEL_2_DATA_RECOVERY_AND_FEASIBILITY.md)
