#!/bin/sh
# Checks the artifacts GoReleaser built into dist/ (a snapshot in CI, or a
# release before it is announced) and that install.sh installs them and
# refuses a tampered archive. Runs on linux/amd64 or linux/arm64.
#
#   scripts/check-release.sh [dist]
set -eu

dist=$(cd "${1:-dist}" && pwd)
root=$(cd "$(dirname "$0")/.." && pwd)
version=v$(sed -n 's/.*"version":"\([^"]*\)".*/\1/p' "$dist/metadata.json")
case $(uname -m) in
x86_64 | amd64) arch=amd64 ;;
aarch64 | arm64) arch=arm64 ;;
*)
	echo "no build for $(uname -m)" >&2
	exit 1
	;;
esac
fail() {
	echo "check-release: $*" >&2
	exit 1
}

echo "checking $version in $dist"
(cd "$dist" && sha256sum -c --quiet checksums.txt) || fail "checksums.txt does not match the files"
for f in "$dist"/*.tar.gz "$dist"/*.deb "$dist"/*.rpm; do
	[ -s "$f.sbom.json" ] || [ "${SKIP_SBOM:-}" = 1 ] || fail "no SBOM for $(basename "$f")"
done
for a in amd64 arm64; do
	list=$(tar -tzf "$dist/hostlint_${version#v}_linux_$a.tar.gz")
	echo "$list" | grep -qx hostlint || fail "no binary in the $a archive"
done
if command -v dpkg-deb >/dev/null 2>&1; then
	contents=$(dpkg-deb --contents "$dist"/hostlint_*_amd64.deb)
	echo "$contents" | grep -q ' \./usr/bin/hostlint$' || fail "no /usr/bin/hostlint in the .deb"
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

HOSTLINT_DOWNLOAD_URL="file://$dist" sh "$root/install.sh" -v "$version" -b "$tmp/bin"
"$tmp/bin/hostlint" version | grep -qF "$version" || fail "the installed hostlint is not $version"

mkdir "$tmp/tampered"
cp "$dist/checksums.txt" "$dist/hostlint_${version#v}_linux_$arch.tar.gz" "$tmp/tampered/"
# With the signature too, so that a release run (with cosign) fails on the
# checksum, not on a missing file.
[ ! -e "$dist/checksums.txt.sigstore.json" ] || cp "$dist/checksums.txt.sigstore.json" "$tmp/tampered/"
printf x >>"$tmp/tampered/hostlint_${version#v}_linux_$arch.tar.gz"
if HOSTLINT_DOWNLOAD_URL="file://$tmp/tampered" sh "$root/install.sh" -v "$version" -b "$tmp/bin2" 2>/dev/null; then
	fail "install.sh installed a tampered archive"
fi
[ ! -e "$tmp/bin2/hostlint" ] || fail "install.sh left a tampered binary behind"
echo "release artifacts OK"
