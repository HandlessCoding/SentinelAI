"""Generate a tiny synthetic PCAP and exercise the lab workflow without network I/O."""

import argparse
from datetime import UTC, datetime
from ipaddress import IPv4Address
import json
from pathlib import Path
from struct import pack, unpack
import subprocess
import sys

from ml.lab_capture import audit
from ml.lab_registry import DEFAULT_ROOT, register, write_new_object
from ml.lab_zeek import run_zeek


START = 1_767_225_600


def utc(second):
    return datetime.fromtimestamp(second, UTC).isoformat().replace("+00:00", "Z")


def ethernet_frame(source, destination, origin_port, response_port, payload, packet_id, reverse):
    ip = pack("!BBHHHBBH4s4s", 0x45, 0, 28 + len(payload), packet_id, 0, 64, 17, 0,
              IPv4Address(source).packed, IPv4Address(destination).packed)
    total = sum(unpack("!10H", ip))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    ip = ip[:10] + pack("!H", ~total & 0xffff) + ip[12:]
    macs = [bytes.fromhex("020000000001"), bytes.fromhex("020000000002")]
    if reverse:
        macs.reverse()
    ethernet = macs[1] + macs[0] + b"\x08\x00"
    udp = pack("!HHHH", origin_port, response_port, 8 + len(payload), 0)
    return (ethernet + ip + udp + payload).ljust(60, b"\0")


def demo(root, zeek_binary=None):
    root.mkdir(parents=True, exist_ok=False)
    drafts = []
    pcap = bytearray(pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    for index, offset in enumerate((1, 4, 7), 1):
        source, destination = "192.0.2.1", "192.0.2.2"
        client_port, server_port = 45000 + index, 45010
        for reverse in (False, True):
            endpoints = (destination, source, server_port, client_port) if reverse else (
                source, destination, client_port, server_port
            )
            frame = ethernet_frame(*endpoints, b"test", index * 2 + int(reverse), reverse)
            pcap.extend(pack("<IIII", START + offset, 125000 * reverse, len(frame), len(frame)) + frame)
        drafts.append({
            "ts": START + offset, "uid": f"fixture-{index}", "proto": "udp", "duration": 0.125,
            "id.orig_h": source, "id.resp_h": destination, "id.orig_p": client_port, "id.resp_p": server_port,
            "conn_state": "SF", "orig_pkts": 1, "resp_pkts": 1, "orig_ip_bytes": 32, "resp_ip_bytes": 32,
            "orig_bytes": 4, "resp_bytes": 4, "missed_bytes": 0,
        })
    (root / "fixture.pcap").write_bytes(pcap)
    evidence = {"fixture_only": True, "benign_window": "ordinary UDP fixture",
                "attack_window": "test label only, ordinary UDP fixture packets",
                "unreviewed_window": "unknown fixture"}
    write_new_object(root / "evidence.json", evidence)
    manifest = {
        "version": 1, "capture_id": "fixture", "session_id": "synthetic-session",
        "environment_id": "synthetic", "device_ids": ["fixture-a", "fixture-b"],
        "observation_point": "generated-ethernet", "collection_profile": "demo",
        "scenario": "pipeline-smoke-test", "source": "synthetic", "role": "fit",
        "start": utc(START), "end": utc(START + 9), "pcap": "fixture.pcap",
        "conn_log": "fixture-conn.jsonl",
        "windows": [
            {"start": utc(START), "end": utc(START + 3), "label": "benign"},
            {"start": utc(START + 3), "end": utc(START + 6), "label": "attack", "category": "fixture-only"},
        ],
    }
    for window in manifest["windows"]:
        window.update(evidence="evidence.json", evidence_kind="synthetic_fixture", author="fixture-author",
                      reviewer="fixture-reviewer", scope="all_observed_flows")
    if zeek_binary:
        run_zeek(root, "fixture.pcap", "fixture", zeek_binary)
        manifest.update(conn_log="zeek/fixture/conn.log", zeek_receipt="zeek/fixture/run.json")
    else:
        with (root / "fixture-conn.jsonl").open("x", encoding="utf-8") as stream:
            for row in drafts:
                stream.write(json.dumps(row) + "\n")
    write_new_object(root / "capture-draft.json", manifest)
    register(root, manifest)
    return audit(root, ["fixture"])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT / "demo")
    parser.add_argument("--zeek-binary", help="optional trusted Zeek binary on a configured host")
    args = parser.parse_args(argv)
    try:
        print(json.dumps(demo(args.root, args.zeek_binary), indent=2, sort_keys=True))
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"Synthetic demo stopped: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
