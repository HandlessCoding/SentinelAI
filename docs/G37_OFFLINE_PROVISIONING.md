# G37 offline provisioning preparation

**Status.** Candidate manifest and host-side verification only. APT closure and a PostgreSQL 16 runtime check are pending. [Approved procedure and pilot gates](adr/0002-g37-sensor-local-postgresql.md) · [Candidate manifest](../examples/g37_t4_candidate_manifest.json)

## Verified inventory

| Item | Observation on 22 November 2026 |
| --- | --- |
| VirtualBox and sensor | VirtualBox 7.2.8 r173730. Sensor powered off, 1 vCPU, 2 GiB assigned RAM, BIOS, and the `g26-clean-isolated` snapshot present. Adapter 1 is Internal Network only. Adapters 2–8 are disabled. |
| Guest and storage | Ubuntu 24.04.5 LTS (`noble`), amd64, installed kernel 6.8.0-147-generic. The active two-file VDI chain exposes a 10 GiB virtual disk and a 9 GiB ext4 root. Clean offline metadata reports 6.34 GiB unreserved free. |
| Python | CPython 3.12.3, Ubuntu build `3.12.3-1ubuntu0.17`, SOABI `cpython-312-x86_64-linux-gnu`, glibc `2.39-0ubuntu8.9`. The package inventory has no `python3.12-venv` or pip package. |
| Zeek and PostgreSQL | Zeek and its installed components are `1:8.0.11-0`. tcpdump is `4.99.4-3ubuntu4.24.04.1`. The 693 installed dpkg entries contain no PostgreSQL package or `libpq5`. |
| Read-only optical feasibility | The IDE controller already presents the G26 bootstrap VISO as an optical device, and the installed guest kernel exposes `sr_mod` and `isofs`. G26 exercised the optical path. Preserve the seed and use an approved optical slot on the rehearsal clone. Actual ISO detection, read-only mounting, guest routes, runtime memory, and filesystem capacity under load require booted evidence. |

VirtualBox supplied the configuration and the active VDI chain was read as binary data without a filesystem mount. Inventory was limited to OS, disk, driver, and package metadata. [VirtualBox virtual storage](https://docs.oracle.com/en/virtualization/virtualbox/7.2/user/storage.html) · [G26 optical and package evidence](research/lab/LEVEL_2_G26_ZEEK_VERIFICATION.md)

## Candidate pins and evidence

- Freeze SentinelAI at `38f9f7ed8c0a0dc226380ce2cdd5018142d81bbc` and Alembic at `0004_zeek_browsing`. Retain the observed Zeek, Python, and tcpdump versions. Use the published Zeek 8.0 LTS Noble artifacts if the approved bundle includes their packages. Match the OBS signing key to a separately trusted fingerprint before admitting any Zeek artifact.
- Prefer Noble's PostgreSQL server, client, and `libpq5` at `16.15-0ubuntu0.24.04.1`. Pin server and client common packages at `257build1.1` and `python3.12-venv` at `3.12.3-1ubuntu0.17`, with its Ubuntu bootstrap wheels. PostgreSQL 16 provides the transaction ID and snapshot functions used by SentinelAI. The repository regression gate runs PostgreSQL 18. Verify the migration and worker against the pinned 16.15 build in a separate development environment before freezing the ISO inputs. [PostgreSQL 16 functions](https://www.postgresql.org/docs/16/functions-info.html#FUNCTIONS-PG-SNAPSHOT)
- For the worker and migration runtime, use the existing roots SQLAlchemy `2.0.45`, Alembic `1.17.2`, psycopg with its binary extra `3.3.2`, and python-dotenv `1.2.4`, with pip `26.3` as the venv installer. The ten-wheel Linux CPython 3.12 closure resolved using only the staged wheels and an empty cache. All staged wheels matched exact filenames, sizes, and SHA-256 values in PyPI release metadata. Run the worker and migration imports on the target ABI during verification. [Hash-checked installation](https://pip.pypa.io/en/stable/topics/secure-installs/)
- The installed Ubuntu archive key verified Noble Security and Updates `InRelease` signatures. Their SHA-256 entries authenticated the package indexes, and the indexes authenticated all eight staged Ubuntu files. The manifest records the signer and provenance through each file. These files are a partial APT set. Direct checks still identify `ssl-cert`, `libllvm17t64`, and `libjson-perl` outside the staged or installed set. A matching APT resolver must check all versions, alternatives, virtual packages, pre-dependencies, and conflicts. [APT archive authentication](https://manpages.debian.org/bookworm/apt/apt-secure.8.en.html)

## Before authorizing the ISO build

1. Use an approved, disposable **non-sensor** Ubuntu Noble amd64 resolver. Apply the recorded installed-package state and a fixed, authenticated Noble base, Security, and Updates snapshot. Resolve the exact roots with a declared recommendation policy. Record the full transaction and installed-package assumptions. Check disk space and reject unexpected upgrades, removals, source substitutions, or unresolved dependencies.
2. Check package integrity against the original signed repository metadata, including any OBS packages admitted to the bundle. Make a file-only APT repository for the selected closure and sign its generated index with an approved bundle key scoped through `Signed-By`. Retain the original authenticated metadata separately from that generated index. Run an offline APT simulation using only the staged repository and baseline state.
3. In the disposable development environment, verify Python imports and dependency consistency, run Alembic to the pinned revision against PostgreSQL 16.15, and confirm the existing worker can commit one synthetic flow and its checkpoint. Freeze the reviewed source, package names, exact file bytes, origins, versions, and SHA-256 values. Record the proposed ISO builder/version, file order, volume label, and fixed timestamps. Obtain approval for the verified bundle inputs before building.

## Approved-build and later installation checklist

- With build approval, produce the ISO reproducibly. Verify its filesystem listing and every member digest from the resulting image, then hash the complete ISO. Retain the approved manifest and ISO digest in independently trusted storage on the host, outside the ISO.
- With separate rehearsal authorization, verify the exact ISO digest before attaching it as read-only data media to the disposable clone. Confirm guest compatibility and isolation, resolve only from the mounted repository and wheelhouse, and verify installed versions, source SHA, imports, dependencies, and Alembic revision. Keep PostgreSQL stopped until its loopback-only configuration and local credentials are ready. Verify listener state and a committed benign flow and checkpoint.
- A failed integrity, isolation, dependency, migration, or ingestion check leaves the pilot stopped. Preserve sanitized evidence and return to the authorized clean baseline before retrying. The rehearsal and live pilot require separate approvals. [Rehearsal acceptance](adr/0002-g37-sensor-local-postgresql.md#required-offline-installation-rehearsal)
