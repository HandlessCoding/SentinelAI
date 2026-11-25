#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
test "$(ls /sys/class/net)" = lo
test "$(wc -l < /proc/net/route)" -eq 1
test "$(cat /sys/fs/cgroup/cpu.max)" = '100000 100000'
test "$(cat /sys/fs/cgroup/memory.max)" -eq 2147483648
test "$(cat /sys/fs/cgroup/memory.swap.max)" -eq 0
export APT_CONFIG=/tmp/g37-file-only.conf
printf 'Dir::Etc::sourcelist "/dev/null";\nDir::Etc::sourceparts "/dev/null";\n' > "$APT_CONFIG"
cd /stage
sha256sum -c SHA256SUMS
printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d
chmod 755 /usr/sbin/policy-rc.d
apt-get --no-install-recommends -y install /stage/debs/*.deb
while IFS= read -r root; do
  test "$(dpkg-query -W -f='${Version}' "${root%%=*}")" = "${root#*=}"
done < /stage/apt-roots
apt-get --no-download check
test "$(python3.12 --version)" = 'Python 3.12.3'
python3.12 -m venv /tmp/g37-venv
export PIP_CONFIG_FILE=/dev/null PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1
/tmp/g37-venv/bin/python -m pip install --no-index --find-links /stage/wheels \
  --only-binary ':all:' --require-hashes -r /stage/wheels.lock
/tmp/g37-venv/bin/python -m pip check
pg_lsclusters --no-header
printf "listen_addresses = '127.0.0.1'\n" > /etc/postgresql/16/main/conf.d/g37-loopback.conf
cd /sentinelai
PYTHONPATH=/sentinelai /tmp/g37-venv/bin/python -B /harness/smoke.py
