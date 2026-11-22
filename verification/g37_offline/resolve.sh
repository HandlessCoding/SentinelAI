#!/usr/bin/env bash
set -euo pipefail
test "$(dpkg --print-architecture)" = amd64
. /etc/os-release
test "$VERSION_CODENAME" = noble
dpkg-query -W -f='G37_BASE ${Package}\t${Version}\t${Architecture}\n'
mkdir -p /stage/debs/partial
chmod 755 /stage/debs/partial
cat > /etc/apt/sources.list.d/ubuntu.sources <<'EOF'
Types: deb
URIs: https://snapshot.ubuntu.com/ubuntu/20261122T130000Z/
Suites: noble noble-updates noble-security
Components: main universe
Architectures: amd64
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
EOF
apt-get -o Acquire::https::CaInfo=/host-ca.pem -o Acquire::Languages=none update
for release in /var/lib/apt/lists/*_InRelease; do
  gpgv --status-fd 1 --keyring /usr/share/keyrings/ubuntu-archive-keyring.gpg "$release" \
    | grep -F 'VALIDSIG F6ECB3762474EDA9D21B7022871920D1991BC93C'
  sha256sum "$release"
done
mapfile -t roots < /stage/apt-roots
apt-get --simulate --no-install-recommends install "${roots[@]}"
apt-get -o Acquire::https::CaInfo=/host-ca.pem \
  -o Dir::Cache::archives=/stage/debs/ \
  --download-only -y --no-install-recommends install "${roots[@]}"

cd /stage
size_kib=0
for package in debs/*.deb; do
  name=$(dpkg-deb -f "$package" Package)
  version=$(dpkg-deb -f "$package" Version)
  arch=$(dpkg-deb -f "$package" Architecture)
  test "$arch" = amd64 || test "$arch" = all
  kib=$(dpkg-deb -f "$package" Installed-Size)
  hash=$(sha256sum "$package" | cut -d ' ' -f1)
  metadata=$(apt-cache show "$name=$version")
  printf '%s\n' "$metadata" | grep -Fxq "SHA256: $hash"
  filename=$(awk '/^Filename: / {print $2; exit}' <<< "$metadata")
  printf 'G37_DEB %s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$name" "$version" "$arch" "$kib" "$hash" "$(stat -c '%s' "$package")" "$filename"
  size_kib=$((size_kib + kib))
done
printf 'G37_APT_INSTALLED_KIB %s\n' "$size_kib"
sha256sum debs/*.deb wheels/*.whl > SHA256SUMS
