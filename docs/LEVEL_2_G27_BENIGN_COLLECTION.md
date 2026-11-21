# G27 Automated benign collection and quality validation

## Collection design

G27 uses the same two Ubuntu guests, the `sentinelai-g26-intnet` VirtualBox
Internal Network, and Zeek 8.0.11 installed in G26. The sensor records traffic on
`lab0`. Before either phase, the powered-off VirtualBox configuration must show
one Internal Network adapter and seven disabled adapters on each guest. Both
guests then verify their addresses, interfaces, routes, and forwarding settings.
Local route lookups for the Windows host, LAN gateway, and internet addresses
send no traffic. The sensor starts the recorder only after the verified client
reaches its dedicated local coordinator. Coordinator traffic is excluded from
the PCAP. [G26 verification](LEVEL_2_G26_ZEEK_VERIFICATION.md) ·
[VirtualBox network modes](https://docs.oracle.com/en/virtualization/virtualbox/7.2/user/networkingdetails.html)

Each plan uses ordinary HTTP GET and POST over TCP and request/response datagrams
over UDP. Each plan entry describes a connection, with one to four transactions
on that connection. It specifies payload bounds, a response delay and a gap
between transactions. A per-session seed determines sizes and bytes. It does
not fix Linux ephemeral ports, scheduling jitter, packet segmentation, or
timestamps. HTTP includes single requests and persistent connections. The
UDP digest service is a small application fixture. Its traffic is UDP and does
not represent DNS or a production application.

The generator supports at most eight sessions per batch, sixteen connections
per session, four transactions per connection, a 16 KiB HTTP payload, and a
512-byte UDP application payload. The fixed endpoints are the two owned G26
guest addresses. Tcpdump is scoped to their two authorized data services,
uses a packet cap, and stops between sessions. The batch is bounded by a
five-minute sensor deadline. The original PCAP and Zeek receipt stay on D:.

## Evidence and quality gates

The client logs completed requests and checked replies. The service records its
own observations of the requests and the replies it sent. The review compares
each side against the fixed plan using transaction IDs, lengths, and payload
hashes. It uses connection tuples to join the event evidence to Zeek, verifies
bidirectional packet counters, and checks that sensor events align with the
capture and flow bounds. Labels depend on the completed application evidence.
The whole capture stays unknown if any connection cannot be attributed.

The pilot must contain one flow for every planned connection, with the expected
transport, valid duration and directional counters, matching application
evidence, and matching tcpdump and Zeek packet totals. Kernel drops, malformed
records, invalid feature values, unexplained flows, or unverified labels
block expansion. Missing optional fields are recorded separately. An unknown
Zeek service on the custom UDP application is expected. A missing essential
counter or duration blocks attribution. The G25 registry pins the original
PCAP, Zeek log, receipt, and reviewed evidence.
[Zeek connection fields and units](https://docs.zeek.org/en/v8.0.11/scripts/base/protocols/conn/main.zeek.html#type-Conn::Info)

The combined audit checks duplicate PCAP and Zeek-log hashes, exact feature
vectors within and across sessions, known-label conflicts, capture-window overlap,
and per-session coverage. Repeated vectors remain in place. The registry's
`fit` field is a required G25 placeholder for this development collection.
No calibration, model comparison, or validation cohort was assigned.

## Reproduce a bounded batch

Use the G26 guest configuration and confirm the VirtualBox settings before
booting. Place the tracked Python source, one plan, and a private `routes.json`
on read-only media. The route file maps `host`, `lan_gateway`, `internet_ipv4`,
and `internet_ipv6` to representative addresses outside the lab subnet.
Run the sensor workflow in the recording guest and the client workflow in the
client guest. Both run the same plan.

```bash
sudo python3 -B -m ml.lab_benign sensor plan.json routes.json /var/tmp/g27-sensor
sudo python3 -B -m ml.lab_benign client plan.json routes.json /var/tmp/g27-client
```

The sensor logs `G27_SENSOR_READY` after its own isolation checks, before any
recording starts. Use separate output directories per attempt. Each side's
artifacts can be copied as files, or sent through a local VirtualBox serial
file using start/end markers and numbered base64 lines. The G27 handoff sent
only those artifacts over the local console. The importer expects one complete
archive per guest and exact expected paths.

```bash
echo G27_EXPORT_BEGIN
tar -czf - -C /var/tmp/g27-sensor . |
  base64 -w 384 | awk '{printf "G27_EXPORT:%05d:%s\n",NR,$0}'
echo G27_EXPORT_END
```

For the client export, substitute its artifact directory for the sensor path.

```powershell
$lab = 'data/level2/capture-lab/g27'
& .\.venv\Scripts\python.exe -B -m ml.lab_benign_transfer $lab examples/lab_benign_pilot.json $sensorConsole $clientConsole
& .\.venv\Scripts\python.exe -B -m ml.lab_benign_audit $lab "$lab/pilot-quality.json" examples/lab_benign_pilot.json
```

Supply the two local console paths and a local authorization record at
`$lab/evidence/g27-authorization.json` before the audit. Confirm an exit code
of zero and `passes_collection_gates=true` in the pilot report before running
the expansion plan. Run the final report with both plan files to audit their
combined capture and session evidence.

## Results and next experiment

The first pilot attempt completed its five application transactions. Tcpdump
reported 34 packets received by the filter, zero delivered to the savefile,
and a 24-byte PCAP header. Zeek produced no flows, so that attempt stayed
outside the registry. The original attempt remains on the sensor disk on D:.
The retry used a fresh capture and session ID, the same seed and workload,
tcpdump immediate mode, and a 1.25-second post-transaction interval. It produced
36 packets and three verified flows, with zero kernel drops. Expansion started
after its matching packet counts, evidence, and isolation checks passed.
[tcpdump immediate mode](https://github.com/the-tcpdump-group/tcpdump/blob/master/tcpdump.1.in)

### Verified recordings

Counts below are from the four registered recordings. Packet and IP octet
pairs are originator / responder as observed by Zeek. Durations show
minimum / median / maximum in milliseconds, rounded for display.

| Capture | Seed | Transactions | TCP / UDP flows | Packets | IP octets | Duration (ms) | PCAP bytes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `g27-pilot-02` | 2701 | 5 | 2 / 1 | 19 / 17 | 2,354 / 1,731 | 85.147 / 129.972 / 301.783 | 5,189 |
| `g27-expand-02` | 2702 | 10 | 3 / 1 | 37 / 32 | 5,989 / 4,972 | 179.451 / 259.849 / 345.116 | 13,055 |
| `g27-expand-03` | 2703 | 10 | 3 / 2 | 47 / 44 | 12,732 / 17,784 | 5.825 / 258.308 / 723.378 | 33,270 |
| `g27-expand-04` | 2704 | 8 | 3 / 1 | 37 / 33 | 3,552 / 10,339 | 85.411 / 538.889 / 1,026.711 | 16,015 |
| **Combined** | | **33** | **11 / 5** | **140 / 126** | **24,627 / 34,826** | **5.825 / 258.602 / 1,026.711** | **67,529** |

The 33 completed transactions comprised 14 GET requests, seven POST requests,
and 12 UDP exchanges. Tcpdump recorded 266 packets with zero kernel drops
across the four successful captures. Zeek 8.0.11 accounted for all 266 packets.
All 16 flows were reviewed as benign. There were zero unknown and zero attack
flows in the four registered captures. Zeek reported 17,547 originator and
28,474 responder payload bytes, zero missed bytes, and connection state
`SF` for all 16 flows.

The audit parsed all rows successfully. Timestamps, duration, transport, state,
history, and all directional counters were complete in every session.
The single missing field type was `service`. It was unset on all five UDP
flows and `http` on all 11 TCP flows. The combination contained zero invalid
feature values.

The four original capture windows were disjoint. There were four distinct
session IDs, four distinct PCAP hashes, and four distinct Zeek-log hashes.
The 16 core vectors and 16 richer vectors were all distinct. There were
zero cross-session repeated core keys and zero known-label conflicts. A
benign-only collection provides no two-class evidence about label conflicts.
The combined report and detailed checksums are under
`data/level2/capture-lab/g27/`, including `expansion-quality.json` and the four
registry entries.

All sessions share the same physical host, two guests, software images, sensor
configuration, and isolated network. Separate session IDs and disjoint capture
windows represent repeated runs of this lab. These captures cannot establish
device independence, environment transfer, or a deployment false-positive rate.

Both VMs are powered off with their original idle boot media and clean
snapshots. The Windows suite ran 167 Python tests with 166 passes and one skip
for the Linux-only Zeek executable. Actual G27 PCAP processing used the
installed Zeek executable in the Ubuntu sensor. All 22 frontend tests passed
and the production build succeeded. The frozen Level 1 checksum matched.
The reserved 2018 benchmark stayed sealed, and no model or threshold changed.

For G28, repeat one frozen benign plan in a separately provisioned and
authorized environment with an independent device lineage and observation
point. Keep the complete new recording outside development until the feature
and evidence checks are fixed. Compare coverage, optional-feature availability,
and the prevalence of repeated vectors before adding labels from a different
source.
