# Isolated Ubuntu development

Use **SentinelAI-Ubuntu-Final** for Ubuntu development. Start that VM from
VirtualBox Manager and use its console. All eight network adapters are disabled.
The guest has 2 vCPUs, 4 GiB of RAM, and a 32 GiB dynamically allocated VDI.

| Role | VirtualBox machine UUID | Attached VDI UUID |
| --- | --- | --- |
| Development | `ffacb360-9283-4210-ab9a-3f9c217907ca` | `a3027b9b-9faf-444a-9cad-aeac047a401a` |
| Recovery only | `4b482edf-6b7c-4afc-aa22-43787a5bf0e5` | `6fd8f0c7-94ff-41c4-bc03-ad01cb276982` |

The development disk is under `data/development-vm/SentinelAI-Ubuntu-Final/`.
The backup `SentinelAI-Ubuntu-Backup` is under `D:/vmMachines/`, outside the
checkout. VirtualBox reports distinct base VDIs with no parent disk. Both
machines currently reference the same read-only v3 DVD. Keep that media at
its recorded path. Restoration from the backup remains untested.

## Daily use

Sign in at the guest console. Work in `~/sentinelai` with its Python 3.12
virtual environment and private `.env`. PostgreSQL and FastAPI use guest
loopback addresses. Apply pending migrations to the intended development
database through the [database guide](DATABASE_SETUP.md) when a change adds
one.

```bash
cd ~/sentinelai
pg_isready -h 127.0.0.1
.venv/bin/python -B -m alembic current
.venv/bin/python -B -m uvicorn backend.main:app --host 127.0.0.1 --port 8001
```

If PostgreSQL is stopped, use `sudo systemctl start postgresql`. In a separate
guest terminal, check `curl --fail http://127.0.0.1:8001/health`. Use the
[documented synthetic tests](RELIABILITY_TESTING.md) for regression work.
The Windows checkout provides the frontend toolchain and local static checks.

Shut down with `sudo poweroff` and wait for **Powered Off** in VirtualBox
Manager. Use ACPI Shutdown from the VirtualBox menu if a normal console
shutdown is unavailable. Check `sudo journalctl -u postgresql` for service
startup failures.

## Recovery and evidence

Verify the recorded media digest before any recovery use. The
[offline closeout](G37_OFFLINE_PROVISIONING.md) identifies the guest-tested
v3 install, sealed v4 installer, and the evidence behind each. Keep recovery
and significant infrastructure changes subject to operator approval.
G26 guests are protected research references. G37 rehearsal scripts and
checkpoint procedures are historical. Use the [lab guide](LAB_GUIDE.md) for
the separately authorized research workflow.