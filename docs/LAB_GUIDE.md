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
