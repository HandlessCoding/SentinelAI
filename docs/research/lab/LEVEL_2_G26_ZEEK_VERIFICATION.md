# G26 Isolated Linux lab and Zeek verification

## Preflight

| Item | Observed or planned |
| --- | --- |
| Host | AMD Ryzen 5 5600H with 12 logical CPUs and firmware virtualization enabled |
| Memory | 31.4 GiB installed, 15.0 GiB available at preflight |
| Storage | 163.6 GiB free on D: and 149.9 GiB free on C: at preflight |
| VirtualBox | 7.2.8 r173730, three existing VMs listed and none running |
| Default VM location | D: already holds the VirtualBox machine folder |
| New guests | `sentinelai-g26-client` and `sentinelai-g26-sensor`, each verified with 1 vCPU, 2 GiB RAM, and a dynamically allocated 10 GiB VDI |
| Lab location | `data/level2/capture-lab/g26/` on D:, including guest disks, captures, evidence, and logs |
| Installation source | Official Canonical Ubuntu Server 24.04 LTS amd64 appliance, listed at about 563 MiB and reused for both guests |

The approved Canonical image was build 20261017, 590,766,080 bytes.
Its SHA-256 was `ce599f89777c6eaa1a3156698f004b7938dcc16680132d5f10da1269770e74a2`.
Before import, the digest matched the Canonical checksum manifest and GnuPG
verified its signature using the documented cloud-image key fingerprint
`D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81`. The three existing VMs and
their disks were outside the build. The sensor uses the documented Ubuntu
24.04 package source for the supported Zeek 8.0 release train.
[Canonical appliance and checksums](https://cloud-images.ubuntu.com/releases/noble/release/) ·
[Canonical checksum verification](https://ubuntu.com/docs/public-images/public-images-how-to/verify-image-checksum/) ·
[Canonical VirtualBox import guide](https://ubuntu.com/docs/public-images/public-images-how-to/run-an-ova-using-virtualbox/) ·
[Zeek supported Ubuntu packages](https://docs.zeek.org/en/current/install.html)

## Stage and verify the guests

1. Import the verified appliance twice into the G26 folder. Use guest-specific
   cloud-init data with unique instance IDs. Keep any generated credentials and
   bootstrap media under the ignored lab directory.
2. During approved provisioning, keep the sensor off the lab network. Use
   temporary NAT only on that sensor to install Zeek and the packet capture
   utility from the approved package sources. The client needs a local HTTP
   client, which can use the Python standard library in the cloud image.
3. Power off the sensor after provisioning and remove the NAT adapter.
   Connect each guest's sole enabled adapter to the same named VirtualBox
   Internal Network. Assign local addresses with an explicit subnet and no
   default gateway. Keep forwarding and host integrations disabled.
4. Inspect powered-off machine settings and verify each guest's IPv4 and IPv6
   route tables after boot. Use local route lookups for representative host,
   LAN, and internet addresses, without sending traffic to them. Confirm local
   client–sensor reachability using the owned guest service. Preserve the
   configuration and route evidence. Stop collection if an external route or
   unexpected adapter is present.
5. Shut both guests down cleanly and take a baseline snapshot of each
   isolated, freshly provisioned VM before the capture experiment.

The OVA defines a bridged adapter. Both new guests were powered off while
their adapters were replaced before the first boot. The NoCloud seeds were
read-only VirtualBox virtual ISOs with a `CIDATA` volume and guest-specific
`meta-data`, `user-data`, and `network-config`. They configured local
`ubuntu` console access with generated credentials stored only under the
ignored lab directory. The client seed used its static lab interface. The
first sensor seed named a lab NIC absent during provisioning, so cloud-init
failed to write Netplan. The provisioning retry used a seed that named only
the temporary DHCP interface. The sensor required an abrupt power-off after
the failed first boot ignored ACPI shutdown. Linux recovered its new guest
filesystem journal on the provisioning retry. Keep provisioning and final
network seeds separate.

The sensor installed Zeek 8.0.11 (`zeek-8.0 1:8.0.11-0`) and tcpdump
4.99.4 from signed package repositories. After provisioning, both guests were
powered off with adapters 2 through 8 disabled and adapter 1 set only to
`sentinelai-g26-intnet`. Each guest saw only loopback and its static lab
interface. Neither guest had an IPv4 or IPv6 default route or forwarding.
Local route lookups found no route to the Windows host, LAN gateway, or
representative IPv4 and IPv6 internet addresses. Each guest received both
of its peer ICMP replies. The local raw console logs preserve the evidence.

The dual-vCPU trial showed boot stalls and an unreliable serial pipe.
One vCPU per guest with local raw serial logging completed verification.
Both guests were shut down cleanly and each has a powered-off
`g26-clean-isolated` snapshot. The snapshots were taken before actual traffic
capture and retain the Internal Network settings.

[VirtualBox networking isolation modes](https://docs.oracle.com/en/virtualization/virtualbox/7.2/user/networkingdetails.html) ·
[VirtualBox snapshot commands](https://docs.oracle.com/en/virtualization/virtualbox/7.2/user/vboxmanage.html)

## Verify real Zeek and one benign capture

The real-binary integration test exercises the G25 UDP fixture, including
three connection timestamps, directional counts and byte units, duration, the
reviewed-window labels, and the checksum-pinned registry entry. It requires a
real Zeek executable on Linux and skips with a clear reason when Zeek is
unavailable. Run it from the repository source inside the provisioned guest.

```bash
SENTINELAI_ZEEK_BINARY=/opt/zeek/bin/zeek python3 -B -m unittest discover -s tests -p test_lab_zeek_integration.py -v
```

Also process the existing G25 fixture file within the isolated guest. Compare
its normalized records with the integration assertions. Keep the fixed fixture
hash, real Zeek version, and log checksum in the local verification record.
Use the same version and arguments for the actual benign recording.

The test passed inside the Ubuntu sensor under Zeek 8.0.11. The original
480-byte G25 PCAP also decoded through the production-style runner. Its
SHA-256 was `f79781604010ad73006d42adeeecf33f66d337b5fffac2057102ab8ded11c3c8`.
The tests confirmed the three UDP flows, one packet and 32 IP bytes per
direction on each flow, four payload bytes per direction, and 125 ms
durations.

The benign smoke test is one short exchange between the new client and sensor.
Record the capture start before one ordinary local HTTP request for a
known harmless response. Preserve the client result, service event times,
response evidence, capture bounds, and capture statistics. Process the PCAP
through Zeek offline and transfer the artifacts as files. Pin the original PCAP,
log, and independent scenario evidence using the G25 registry. Check clock
alignment and both directions against the independent event evidence. Use an
approved benign label only for reviewed flow coverage. Any additional
or ambiguous flow remains unknown. The later research cohort needs its own
independent captures.
[G25 registration and labels](LEVEL_2_CONTROLLED_CAPTURE_LAB.md#local-workflow)

### Measured benign recording

| Item | Verified result |
| --- | --- |
| Capture and session | `g26-benign-01-reviewed`, session `g26-http-session-01` |
| Sensor recording bounds (UTC) | 2026-11-21 22:53:19.807753 to 22:54:23.789408 |
| Collection | Sensor `lab0`, tcpdump filter for the approved local service on TCP port 8001, checksum and segmentation offloads disabled on both guests |
| PCAP | 1,325 bytes, 12 packets captured, 12 received by the filter, zero kernel drops |
| Independent evidence | Local client and service event records agreed on HTTP 200, the response length, and the response SHA-256. The service event fell inside the sensor recording. |
| Zeek | One TCP connection with `http` service and `SF` state, seven originator and five responder packets |
| Directional bytes | 502 originator and 439 responder IP octets, with 130 and 171 payload bytes |
| Reviewed labels | One benign, zero attack, zero unknown in the reviewed registration |

Real Zeek emitted the duration as `0.028464078903198242` seconds. The original
parser rejected the extra precision. The corrected parser rounds observed
positive durations of at least one nanosecond up to the next whole nanosecond
when needed, preserving exact timestamps and avoiding a shortened flow in
window attribution. It normalized this flow to 28,464,079 ns. The original
`g26-benign-01` registry record remains unknown. The reviewed revision shares
the same original session and hashes, and pins the separate client and service
evidence. Use only the reviewed revision when counting this capture.

The original PCAP SHA-256 is
`ad91ff828bc3d429ec42b1deb3e1e26984a9ffc26f25421870e6edc6d16738fa`.
The Zeek connection log SHA-256 is
`125de6df656b29fbd3903463421629fd7a8cc5b6914f140eed14bfcda95693ea`.
The receipt, evidence, original recording, and both registry manifests are
under the ignored G26 lab folder on D:. Windows can rerun the recorded-capture
test against that registry.

```powershell
$env:SENTINELAI_G26_LAB_ROOT = (Resolve-Path 'data/level2/capture-lab/g26').Path
& .\.venv\Scripts\python.exe -B -m unittest discover -s tests -p test_lab_zeek_integration.py -v
```

The Windows Python suite ran 161 tests with 160 passes, including the recorded
capture, and one skip for the Linux Zeek executable. That integration test
passed independently inside the sensor with the final parser. All 22
frontend tests passed and the production build succeeded. The frozen Level 1
pipeline matched its pinned SHA-256.

## Readiness

The two guests use VirtualBox Internal Networking and retain their clean
snapshots. Both guests were left powered off. The VDI files, including snapshot
differences, occupied about 2.93 GiB on D: for the sensor and 1.90 GiB for the
client. D: had 155.3 GiB free after verification.

The verified pipeline can collect and process additional authorized
benign sessions. Cohort readiness still requires independent captures,
reviewable negatives and positives, and the G25 coverage gates. G26 collected
one benign session and fit zero models. Independently labeled existing
recordings are the next candidate for positive evidence under a separate
approval. The Level 1 application and frozen model were preserved, and the
reserved NF-CSE-CIC-IDS2018 data stayed outside the workflow.
