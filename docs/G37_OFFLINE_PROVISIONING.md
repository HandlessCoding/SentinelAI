# G37 offline provisioning and development closeout

## Demonstrated on SentinelAI-Ubuntu-Final

The archived guest result identifies VM `ffacb360-9283-4210-ab9a-3f9c217907ca`
and development disk `a3027b9b-9faf-444a-9cad-aeac047a401a`. The checks were
performed offline with all eight VirtualBox adapters disabled. The completed
run used v3 for package installation and a separate application resume after
a mount-directory permissions issue. During repository cleanup the host
rechecked VM configuration and ISO digests with both guests powered off.

| Check | Recorded result |
| --- | --- |
| Offline APT | v2 stopped at the removal guard. Its newer Python standard library lacked the matching `libpython3.12t64` package. v3 supplied it. Guest simulation selected five upgrades and 15 new packages with zero removals or downgrades. Its dpkg state was unchanged by simulation. The installed entry count rose from 695 to 710. |
| PostgreSQL | Server package `16.15-0ubuntu0.24.04.1`. The application database query passed. |
| Zeek | Core package `1:8.0.11-0`. An offline Zeek initialization check passed. |
| Python | CPython 3.12.3, Ubuntu package `3.12.3-1ubuntu0.17`. The offline application resume completed using the guest virtual environment. |
| Migrations and API | Alembic reached `0004_zeek_browsing`. Backend health reported `ok` after the application resume. |
| Synthetic ingestion | The worker committed a synthetic flow. The flow and checkpoint survived a PostgreSQL restart. |
| Duplicate replay | After worker restart and replay, the worker retained one flow, counted one duplicate, advanced the checkpoint to byte 160 and drained the backlog to zero. |

The local evidence directory is
`artifacts/sentinelai-final-development/apt-removal-investigation-v1/`.
It holds `final-guest-results.json`, `final-guest-checks.png`,
`backend-completion.png`, `live-apt-status-proof.png`, the dependency plan,
and the complete v3 and v4 media manifests. These records describe a
development smoke. Live packet capture, native Zeek-to-worker handoff,
detection quality, live sensor capacity, and recovery from the backup
remain unverified. [Pilot acceptance criteria](adr/0002-g37-sensor-local-postgresql.md)

## Offline media retained

| Media | SHA-256 | Verification |
| --- | --- | --- |
| `sentinelai-offline-install-v3.iso` | `3f6e0266eed065627e9bff18a3545e6fdc72bbb887a909b1922076a3d87f1162` | Guest APT and resumed runtime demonstrated. Both VM optical configurations refer to this DVD. |
| `sentinelai-offline-install-v4.iso` | `8b076c15f28c87b11a481263ea26a689d8bb41eecd07de48fa6225e1fba3a9b1` | Sealed media independently read and verified. Same APT transaction as v3, with a mount-directory permission fix. A fresh end-to-end v4 installation is unverified. |

Keep the authenticated Ubuntu Server 24.04.5 LTS installer and its signature
records alongside the application media. The pinned T4 sensor candidate and
its provenance are separate research evidence.

## VM setup retrospective

1. **Keep the isolation and dependency checks.** VirtualBox supplied NAT
   when an adapter section was omitted. Verify adapter settings on the VM
   itself. The APT removal guard protected the guest from a real partial
   Python upgrade. Simulate against the actual target, then verify the
   package transaction, migration, and runtime.
2. **Use ordinary VM operations for daily development.** Rehearsal launchers
   stopped at PowerShell policy, CRLF parsing, VBox process-count assumptions,
   and timestamp precision changes. Use VirtualBox Manager, one development
   VM and a recovery copy. Add automation when it addresses a repeatable
   failure with a testable impact.
3. **Keep evidence with the exact artifact.** Distinguish a package simulation,
   a completed guest run, and a sealed replacement image. Preserve the
   decisive receipts and hashes. The [Ubuntu guide](UBUNTU_DEVELOPMENT.md)
   owns daily setup, and the [roadmap](ROADMAP.md) owns milestone status.

## Historical T5 sensor rehearsals

The attempts below exercised the candidate from the G26 sensor baseline.
The development smoke above ran on a different Ubuntu package baseline.

| Attempt | Recorded result |
| --- | --- |
| 01 | Installed the exact candidate APT transaction and ten-wheel Python environment. PostgreSQL started on loopback. A Psycopg SQL placeholder error stopped privilege verification before Zeek initialization and ingestion. VirtualBox rewrote the original sensor's settings backup. |
| 02 | Preflight found a default NAT adapter on a powered-off clone. No guest boot or ISO attachment followed. |
| 03 | PowerShell execution policy stopped the launcher before VM commands ran. |
| 04 | The disk was independent and all adapters were disabled. The CRLF disk readback tripped the parser. Later continuation receipts recorded parser and timestamp checks. They did not establish a completed guest rehearsal. |
| Lifecycle fixtures | A process-count guard stopped the second startup experiment after VirtualBox exposed three frontend processes. Fixture startup and shutdown were observed. |

The rehearsal launchers and their VM, disk, snapshot, and checkpoint IDs
apply to those attempts. The local archive
`artifacts/sentinelai-final-development/g37-t5-historical-evidence.zip`
preserves the original reports, receipts, and scripts. Its accompanying CSV
records the original paths and file hashes. The sensor pilot remains pending.
[Approved pilot criteria](adr/0002-g37-sensor-local-postgresql.md)

## Historical T4 sensor provisioning

## Verified inventory

| Item | Observation on 22 November 2026 |
| --- | --- |
| VirtualBox and sensor | VirtualBox 7.2.8 r173730. Sensor powered off, 1 vCPU, 2 GiB assigned RAM, BIOS, and the `g26-clean-isolated` snapshot present. Adapter 1 is Internal Network only. Adapters 2–8 are disabled. |
| Guest and storage | Ubuntu 24.04.5 LTS (`noble`), amd64, installed kernel 6.8.0-147-generic. The active two-file VDI chain exposes a 10 GiB virtual disk and a 9 GiB ext4 root. Clean offline metadata reports 6.34 GiB unreserved free. |
| Python | CPython 3.12.3, Ubuntu build `3.12.3-1ubuntu0.17`, SOABI `cpython-312-x86_64-linux-gnu`, glibc `2.39-0ubuntu8.9`. The package inventory has no `python3.12-venv` or pip package. |
| Zeek and PostgreSQL | Zeek and its installed components are `1:8.0.11-0`. tcpdump is `4.99.4-3ubuntu4.24.04.1`. The 693 installed dpkg entries contain no PostgreSQL package or `libpq5`. |
| Read-only optical feasibility | The IDE controller already presents the G26 bootstrap VISO as an optical device, and the installed guest kernel exposes `sr_mod` and `isofs`. G26 exercised the optical path. Preserve the seed and use an approved optical slot on the rehearsal clone. Actual ISO detection, read-only mounting, guest routes, runtime memory, and filesystem capacity under load require booted evidence. |

VirtualBox supplied the configuration and the active VDI chain was read as binary data without a filesystem mount. Inventory was limited to OS, disk, driver, and package metadata. [VirtualBox virtual storage](https://docs.oracle.com/en/virtualization/virtualbox/7.2/user/storage.html) · [G26 optical and package evidence](research/lab/LEVEL_2_G26_ZEEK_VERIFICATION.md)

## Approved candidate inputs

- Freeze SentinelAI at `38f9f7ed8c0a0dc226380ce2cdd5018142d81bbc` and Alembic at `0004_zeek_browsing`. Retain Zeek, locales, SQLite, the base Python runtime, and tcpdump at their sensor-baseline versions.
- Use the 11 installation packages and eight coordinated glibc and Perl security upgrades at the versions, sizes, and SHA-256 digests in the sensor manifest. This includes PostgreSQL `16.15-0ubuntu0.24.04.1`, server and client common packages `257build1.1`, and `python3.12-venv` `3.12.3-1ubuntu0.17` with its Ubuntu bootstrap wheels. [Approved sensor transaction](../examples/g37_t4_sensor_transaction.json)
- For the worker and migration runtime, use the existing roots SQLAlchemy `2.0.45`, Alembic `1.17.2`, psycopg with its binary extra `3.3.2`, and python-dotenv `1.2.4`, with pip `26.3` as the venv installer. The ten-wheel Linux CPython 3.12 closure resolved using only the staged wheels and an empty cache. All staged wheels matched exact filenames, sizes, and SHA-256 values in PyPI release metadata. Run the worker and migration imports on the target ABI during verification. [Hash-checked installation](https://pip.pypa.io/en/stable/topics/secure-installs/)
- The Ubuntu archive signature authenticates the original Noble, Updates, and Security indexes. These indexes establish the package hashes independently of the candidate's local APT signature. Changes to the approved transaction or wheelhouse require renewed review. [APT archive authentication](https://manpages.ubuntu.com/manpages/noble/man8/apt-secure.8.html)

## Disposable installation evidence

The initial eight-package staging set was an input to dependency discovery. The disposable installation used the larger closure below.

The disposable resolver authenticated the Noble base, Updates, and Security indexes at snapshot `20261122T130000Z` against the Ubuntu archive key. The fresh test container allowed only loopback and used local APT files and an empty pip cache. APT installed 45 new packages and upgraded two, with zero removals and recommendations disabled. The 47 authenticated files total 79.84 MiB compressed, with 319.08 MiB of declared installed size including the two replacement files. All ten hash-pinned wheels installed from the staged wheelhouse and passed `pip check`. [Reproducible workflow and evidence](https://github.com/HandlessCoding/SentinelAI/actions/runs/45048690311)

At 1 vCPU and 2 GiB RAM with swap disabled, PostgreSQL 16.15 listened only on `127.0.0.1:5432`. The migration role reached `0004_zeek_browsing`. The worker role lacked schema creation permission and committed one synthetic flow with the independently derived key and timestamp. Restarting PostgreSQL preserved the row and checkpoint. Restarting the worker and appending the same line advanced the checkpoint to 160 bytes and counted one duplicate while retaining one flow. The smoke took 6.56 seconds wall time and 1.97 CPU-seconds, with about 609 MiB peak cgroup memory including file cache. The PostgreSQL data directory and Python environment used 46.05 MiB and 57.35 MiB of apparent space. Live Zeek and pilot capacity require separate evidence.

## Sensor-baseline APT simulation evidence

The powered-off disk's dpkg status matched the previously recorded inventory byte for byte. All 693 entries were installed, with versions, architectures, and package relationships intact. The read-only extraction recovered APT configuration, sources and preference fragments, and automatic-install state. The dpkg update journal was empty, and no foreign architecture file was present. The disposable Noble amd64 simulation used the same APT and dpkg versions and pointed APT at the recorded status, automatic-install state, and preferences. It replaced the normal Ubuntu and OBS sources with a signed file-only repository and excluded host service hooks. The guest had no network adapter.

The full 47-file offer and reduced 11-file offer both resolve to 11 new installations, zero upgrades, and zero removals. Existing packages meet the dependency constraints. The approved closure adds eight coordinated glibc and Perl security upgrades, with zero removals and zero Zeek changes. The simulation acquired all selected files locally using a temporary key scoped to its simulation repository.

| Package | Recorded sensor | Originally staged | Resolver reason, recommended action, and risk |
| --- | --- | --- | --- |
| `libc6` | `2.39-0ubuntu8.9` | `2.39-0ubuntu8.12` | PostgreSQL and LLVM require at least glibc 2.38, so provisioning alone keeps the installed version. Apply `.12` for the security fixes. The C runtime is used by Zeek and Ubuntu services. Rehearse startup against the updated runtime. |
| `libc-bin` | `2.39-0ubuntu8.9` | `2.39-0ubuntu8.12` | The installed tools accept glibc 2.39 and satisfy the provisioning transaction. Update with `libc6` to keep the C runtime and libc tools at the same patch level. Its triggers refresh the loader cache. |
| `locales` | `2.39-0ubuntu8.9` | `2.39-0ubuntu8.12` | The container needed a locale provider. The sensor already has one and accepts the upgraded `libc-bin`. Retain the installed version to avoid locale regeneration or collation changes during provisioning. |
| `perl` | `5.38.2-3.2ubuntu0.6` | `5.38.2-3.2ubuntu0.7` | `libjson-perl` accepts the installed Perl. Apply `.7` for CVE-2026-82560. The upgraded package requires matching `perl-base` and `libperl5.38t64`. Check PostgreSQL package scripts and existing Ubuntu Perl utilities. |
| `libperl5.38t64` | `5.38.2-3.2ubuntu0.6` | `5.38.2-3.2ubuntu0.7` | Retained by the provisioning-only solve and required at exactly `.7` by upgraded `perl`. Keep the interpreter and shared library in sync for installed Perl consumers. |
| `perl-modules-5.38` | `5.38.2-3.2ubuntu0.6` | `5.38.2-3.2ubuntu0.7` | Retained by the provisioning-only solve. The patched interpreter and shared library require at least `.7`. An older module set would fail the dependency constraints. |
| `libsqlite3-0` | `3.45.1-1ubuntu2.8` | `3.45.1-1ubuntu2.9` | The installed library satisfies Python's dependency. The `.9` package changelog documents a nested-join correctness fix. Retain `.8` for T4 and avoid changing the library used by existing Ubuntu/Python clients. |

The glibc patch also requires matching `libc6-dev` and `libc-dev-bin` because the installed development package uses exact-version dependencies. The recommended Perl transaction includes `perl-base` at `.7` to satisfy its exact dependency. The smaller APT transaction retains the existing Zeek packages and includes no OBS artifacts. The recorded-status simulation verifies package constraints. The separate installation and worker smoke exercise runtime behavior on disposable Ubuntu. The simulation addressed package selection. Guest runtime was assessed separately.

The approved 19-file transaction totals 59.20 MiB of archives and about 169.62 MiB estimated net package growth. A separate disposable repeat smoke used these revisions with the disposable environment's supporting packages and the unchanged ten-wheel lock. It passed migrations, loopback binding, flow and checkpoint persistence, and duplicate suppression at 1 vCPU and 2 GiB RAM. It used 638.54 MiB peak cgroup memory including cache, 2.01 CPU-seconds and 6.56 seconds wall time. [Final disposable verification](https://github.com/HandlessCoding/SentinelAI/actions/runs/45051441705)

## Candidate ISO construction and verification

The candidate `SentinelAI-G37-T4-candidate-38f9f7ed.iso` is 80,015,360 bytes with SHA-256 `f236f8efbc63d3c6266baae83eaf59b66f3b4d99b722208e56aaa9fc3e98d5de`. Two assemblies matched byte for byte. An independent ISO reader verified all members. APT 2.8.3 accepted the files extracted from the image, selected the exact 19-package transaction against the recorded baseline, and rejected an incorrect signing fingerprint in a RAM-only simulation.

- Check each APT archive against the approved manifest and the Ubuntu signature-to-index-to-package chain. Check all ten wheel hashes and sizes against the approved manifest. Export the minimum worker and migration source from the pinned Git commit.
- Sign the file-only APT index with the dedicated candidate key. Scope `Signed-By` to that public keyring and exact fingerprint. Preserve the original Ubuntu evidence, approved input manifest, signing fingerprint, and final ISO digest in protected host storage. Establish the candidate identity from the host records before using the public key carried on the media.
- Record the pinned ISO builder, volume label, file order, and timestamps. Read the finished ISO as a file, check the complete filesystem against an allowlist, and recompute every digest. Verify the extracted APT metadata and compare a second build from the same frozen inputs byte for byte. Keep the construction and verification evidence with the artifact on the host.

The 100,000-row synthetic benchmark exceeded its 90-second drain window. It provides no verified completion time or capacity result at that size. [Synthetic benchmark evidence](RELIABILITY_TESTING.md#g37-verification-to-implement)
