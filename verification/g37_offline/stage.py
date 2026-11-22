"""Stage the public, exact wheels and APT pins from the reviewed manifest."""

import hashlib
import json
import sys
from pathlib import Path
from urllib.request import urlopen


def main(stage):
    manifest = json.loads(Path("examples/g37_t4_candidate_manifest.json").read_text(encoding="utf-8"))
    artifacts = stage / "wheels"
    artifacts.mkdir()
    lock = []
    for wheel in manifest["verified_wheel_candidates"]:
        source, name = wheel["source"], wheel["path"]
        if not source.startswith("https://files.pythonhosted.org/") or Path(name).name != name:
            raise ValueError("Unexpected wheel source or filename")
        with urlopen(source, timeout=30) as response:
            payload = response.read(wheel["bytes"] + 1)
        digest = hashlib.sha256(payload).hexdigest()
        if len(payload) != wheel["bytes"] or digest != wheel["sha256"]:
            raise ValueError(f"Unexpected byte count or digest for {name}")
        (artifacts / name).write_bytes(payload)
        requirement = wheel["name"] + ("[binary]" if wheel["name"] == "psycopg" else "")
        lock.append(f"{requirement}=={wheel['version']} --hash=sha256:{digest}")
        print(f"G37_WHEEL {name} {len(payload)} {digest}")
    (stage / "wheels.lock").write_text("\n".join(lock) + "\n", encoding="ascii")
    roots = manifest["verified_deb_candidates_incomplete"]
    (stage / "apt-roots").write_text(
        "".join(f"{artifact['name']}={artifact['version']}\n" for artifact in roots),
        encoding="ascii",
    )


if __name__ == "__main__":
    main(Path(sys.argv[1]))
