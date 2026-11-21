"""Import bounded G27 artifacts over the VirtualBox serial-console file handoff."""

import argparse
from base64 import b64decode
from io import BytesIO
from pathlib import Path, PurePosixPath
import re
import tarfile

from ml.lab_benign import plan
from ml.lab_registry import lab_path, read_object


MAX_CONSOLE = 24 * 1024**2
MAX_EXPORT = 16 * 1024**2
FRAME = re.compile(rb"G27_EXPORT:([0-9]{5}):([A-Za-z0-9+/=]{1,384})")


def recover_export(console):
    with console.open("rb") as stream:
        content = stream.read(MAX_CONSOLE + 1)
    if len(content) > MAX_CONSOLE:
        raise ValueError("console export exceeds the local size bound")
    markers = re.findall(rb"G27_EXPORT_BEGIN(.*?)G27_EXPORT_END", content, re.DOTALL)
    if len(markers) != 1:
        raise ValueError("expected one completed console export")
    frames = FRAME.findall(markers[0])
    if not frames or [int(index) for index, _ in frames] != list(range(1, len(frames) + 1)):
        raise ValueError("missing, repeated, or unordered console export frames")
    return b64decode(b"".join(chunk for _, chunk in frames), validate=True)


def read_export(console, expected):
    payload = recover_export(console)
    if len(payload) > MAX_EXPORT:
        raise ValueError("compressed export exceeds the local size bound")
    files, size = {}, 0
    with tarfile.open(fileobj=BytesIO(payload), mode="r:gz") as archive:
        for member in archive:
            path = PurePosixPath(member.name)
            if member.isdir():
                if path != PurePosixPath(".") and not any(path in PurePosixPath(name).parents for name in expected):
                    raise ValueError("unexpected export directory")
                continue
            name = path.as_posix()
            size += member.size
            if not member.isfile() or name not in expected or name in files or size > MAX_EXPORT:
                raise ValueError("unexpected or oversized export member")
            files[name] = archive.extractfile(member).read()
    if files.keys() != expected:
        raise ValueError("export is missing expected artifacts")
    return files


def transfer(root, sessions, sensor_console, client_console):
    sensor_names = {name for capture_id in sessions for name in (
        f"raw/{capture_id}.pcap", f"evidence/{capture_id}-sensor.json", f"evidence/{capture_id}-tcpdump.txt",
        f"zeek/{capture_id}/conn.log", f"zeek/{capture_id}/run.json",
    )}
    client_names = {f"evidence/{capture_id}-client.json" for capture_id in sessions}
    files = {**read_export(sensor_console, sensor_names), **read_export(client_console, client_names)}
    for name, data in files.items():
        target = lab_path(root, name)
        if target.exists():
            if target.read_bytes() != data:
                raise ValueError(f"local artifact differs from console export: {name}")
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as stream:
            stream.write(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("plan", type=Path)
    parser.add_argument("sensor_console", type=Path)
    parser.add_argument("client_console", type=Path)
    args = parser.parse_args()
    try:
        transfer(args.root, plan(read_object(args.plan)), args.sensor_console, args.client_console)
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError) as error:
        parser.exit(1, f"Lab export stopped: {error}\n")


if __name__ == "__main__":
    main()
