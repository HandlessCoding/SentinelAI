#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

test "$(dpkg --print-architecture)" = amd64
. /etc/os-release
test "$VERSION_CODENAME" = noble
test "$(ls /sys/class/net)" = lo
awk 'NR > 1 {exit 1}' /proc/net/route
printf 'Ubuntu %s amd64, loopback only, no IPv4 routes\n' "$VERSION_ID"
sha256sum /recorded/status /recorded/extended_states
test "$(grep -c '^Status: install ok installed$' /recorded/status)" -eq 693
dpkg-query --admindir=/recorded -W -f='${Package}\t${Version}\t${Architecture}\n' apt dpkg
apt-get --version | head -n 1

mapfile -t roots < /recorded/apt-roots
work=$(mktemp -d)
chmod 755 "$work"
mkdir -p "$work/preferences" "$work/lists/partial" "$work/empty"
cp /recorded/preferences/* "$work/preferences/"
export APT_CONFIG="$work/apt.conf"
cat > "$APT_CONFIG" <<EOF
Dir::State::status "/recorded/status";
Dir::State::extended_states "/recorded/extended_states";
Dir::State::lists "$work/lists";
Dir::Etc::main "/dev/null";
Dir::Etc::parts "$work/empty";
Dir::Etc::sourcelist "$work/offline.list";
Dir::Etc::sourceparts "$work/empty";
Dir::Etc::preferences "/dev/null";
Dir::Etc::preferencesparts "$work/preferences";
APT::Install-Recommends "false";
Acquire::Languages "none";
EOF

run_simulation() {
  local repo=$1
  shift
  printf '\n=== %s ===\n' "$repo"
  printf 'deb [signed-by=/recorded/sim-key.gpg] file:/repo/%s ./\n' "$repo" > "$work/offline.list"
  apt-get update
  apt-get --simulate check
  apt-cache policy libc6 libc-bin locales perl libperl5.38t64 perl-modules-5.38 libsqlite3-0
  apt-get --simulate --no-remove install "${roots[@]}" "$@" | tee "$work/transaction"
}

run_simulation all
run_simulation minimal
if grep -Eq '^Remv |^Inst [^ ]+ \[|^Inst zeek' "$work/transaction"; then
  printf 'Unexpected package upgrade, removal, or Zeek change\n' >&2
  exit 1
fi
sed -n 's/^Inst \([^ ]*\) (\([^ ]*\) .*/\1=\2/p' "$work/transaction" | sort > "$work/actual"
sort /recorded/minimal-pins > "$work/expected"
diff -u "$work/expected" "$work/actual"
apt-get --assume-yes --download-only --no-remove install "${roots[@]}"
printf '\nG37_SENSOR_SIM_PASS\n'

mapfile -t security < /recorded/security-pins
run_simulation security "${security[@]}"
if grep -Eq '^Remv |^Inst zeek' "$work/transaction"; then
  printf 'Unexpected package removal or Zeek change\n' >&2
  exit 1
fi
sed -n 's/^Inst \([^ ]*\) \(\[[^]]*\] \)\{0,1\}(\([^ ]*\) .*/\1=\3/p' "$work/transaction" | sort > "$work/actual"
sort /recorded/minimal-pins /recorded/security-pins > "$work/expected"
diff -u "$work/expected" "$work/actual"
apt-get --assume-yes --download-only --no-remove install "${roots[@]}" "${security[@]}"
printf '\nG37_SECURITY_SIM_PASS\n'
