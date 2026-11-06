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
	for a in amd64 arm64; do
		contents=$(dpkg-deb --contents "$dist"/hostlint_*_"$a".deb)
		echo "$contents" | grep -q ' \./usr/bin/hostlint$' || fail "no /usr/bin/hostlint in the $a .deb"
		[ "$(dpkg-deb --field "$dist"/hostlint_*_"$a".deb Architecture)" = "$a" ] || fail "the $a .deb has another architecture"
	done
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
if HOSTLINT_DOWNLOAD_URL="file://$tmp/tampered" sh "$root/install.sh" -v "$version" -b "$tmp/bin2" 2>"$tmp/tamper.log"; then
	fail "install.sh installed a tampered archive"
fi
# It must fail on the checksum, not on something else.
grep -q 'does not match its SHA-256' "$tmp/tamper.log" || {
	cat "$tmp/tamper.log" >&2
	fail "install.sh refused the tampered archive for another reason than its SHA-256"
}
[ ! -e "$tmp/bin2/hostlint" ] || fail "install.sh left a tampered binary behind"
# A version is made of what a release tag is made of: it ends up in a URL.
for bad in 'v1/../../evil' 'v1?x' 'latest' 'v1.2.3/../../evil' 'v1.2.3?x' 'v1.2.3 x'; do
	if sh "$root/install.sh" -v "$bad" -b "$tmp/bin3" 2>"$tmp/version.log"; then
		fail "install.sh accepted the version $bad"
	fi
	grep -q 'not a release version' "$tmp/version.log" || fail "install.sh did not reject the version $bad as such"
done
echo "release artifacts OK"
