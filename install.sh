#!/bin/sh
# Install vmsctl from a GitHub release.
#
#   curl -fsSL https://raw.githubusercontent.com/with-developer/vmsctl/main/install.sh | sh
#   sh install.sh -v v0.1.0 -b "$HOME/.local/bin"
#
# The archive must match its SHA-256 in the release's checksums.txt. When
# cosign is installed, the signature of checksums.txt is verified first: it
# must have been signed by this repository's release workflow for that tag.
set -eu

repo=with-developer/vmsctl
version=
bindir=/usr/local/bin

usage() {
	cat <<EOF
Usage: install.sh [-v VERSION] [-b DIR]

  -v VERSION  release to install, such as v0.1.0 (default: the latest)
  -b DIR      directory to install vmsctl into (default: /usr/local/bin)
EOF
}

say() { printf 'install.sh: %s\n' "$*" >&2; }
fail() {
	say "$*"
	exit 1
}

while getopts v:b:h opt; do
	case $opt in
	v) version=$OPTARG ;;
	b) bindir=$OPTARG ;;
	h)
		usage
		exit 0
		;;
	*)
		usage >&2
		exit 2
		;;
	esac
done

[ "$(uname -s)" = Linux ] || fail "vmsctl runs on Linux, not $(uname -s)"
case $(uname -m) in
x86_64 | amd64) arch=amd64 ;;
aarch64 | arm64) arch=arm64 ;;
*) fail "no vmsctl build for $(uname -m)" ;;
esac
command -v curl >/dev/null 2>&1 || fail "curl is required"
command -v tar >/dev/null 2>&1 || fail "tar is required"
command -v sha256sum >/dev/null 2>&1 || command -v shasum >/dev/null 2>&1 || fail "sha256sum or shasum is required to verify the download"

download() {
	curl --proto '=https,file' --proto-redir '=https' --tlsv1.2 -fsSL -o "$2" "$1" || fail "could not download $1"
}

sha256() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | cut -d' ' -f1
	elif command -v shasum >/dev/null 2>&1; then
		shasum -a 256 "$1" | cut -d' ' -f1
	else
		fail "sha256sum or shasum is required to verify the download"
	fi
}

if [ -z "$version" ]; then
	latest=$(curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/$repo/releases/latest") ||
		fail "could not find the latest release"
	case $latest in
	*/tag/*) version=${latest##*/tag/} ;;
	*) fail "$repo has no release yet; choose a version with -v" ;;
	esac
fi
# Only what a release tag is made of: the version becomes part of a URL and
# of the signing identity.
case $version in
v[0-9]*.[0-9]*.[0-9]*)
	case ${version#v} in
	*[!0-9A-Za-z.+-]*) fail "not a release version: $version" ;;
	esac
	;;
*) fail "not a release version: $version" ;;
esac

# Releases before v0.27.0 were published as hostlint (ADR 0017): their archive, binary and signing identity carry
# that name, so an old version is installed under it, from the repository as it was then named (GitHub redirects).
# With a download URL (VMSCTL_DOWNLOAD_URL, or the old HOSTLINT_DOWNLOAD_URL: a mirror, or the snapshot build that CI
# tests) the archive is named for the new project whatever its version.
name=vmsctl
rel=${version#v}
major=${rel%%.*}
rest=${rel#*.}
minor=${rest%%.*}
download_url=${VMSCTL_DOWNLOAD_URL:-${HOSTLINT_DOWNLOAD_URL:-}}
if [ -z "$download_url" ] && [ "$major" = 0 ] && [ "$minor" -lt 27 ] 2>/dev/null; then
	name=hostlint
	repo=with-developer/hostlint
fi

# VMSCTL_DOWNLOAD_URL replaces the release URL; CI uses it to test this
# script against a snapshot build.
base=${download_url:-https://github.com/$repo/releases/download/$version}
[ -z "$download_url" ] || say "warning: downloading from VMSCTL_DOWNLOAD_URL, not from GitHub"
archive="${name}_${version#v}_linux_$arch.tar.gz"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
trap 'exit 130' INT TERM

say "downloading $name $version for linux/$arch"
download "$base/$archive" "$tmp/$archive"
download "$base/checksums.txt" "$tmp/checksums.txt"

if command -v cosign >/dev/null 2>&1; then
	download "$base/checksums.txt.sigstore.json" "$tmp/checksums.txt.sigstore.json"
	cosign verify-blob "$tmp/checksums.txt" \
		--bundle "$tmp/checksums.txt.sigstore.json" \
		--certificate-identity "https://github.com/$repo/.github/workflows/release.yml@refs/tags/$version" \
		--certificate-oidc-issuer https://token.actions.githubusercontent.com >"$tmp/cosign.log" 2>&1 || {
		cat "$tmp/cosign.log" >&2
		fail "the signature of checksums.txt does not verify; not installing"
	}
	say "verified the signature of checksums.txt"
else
	say "cosign not found: checking the SHA-256 only (install cosign to also verify the signature)"
fi

want=$(awk -v f="$archive" '$2 == f { print $1 }' "$tmp/checksums.txt")
[ -n "$want" ] || fail "checksums.txt has no entry for $archive"
[ "$(sha256 "$tmp/$archive")" = "$want" ] || fail "$archive does not match its SHA-256 in checksums.txt; not installing"

tar -xzf "$tmp/$archive" -C "$tmp" "$name"
mkdir -p "$bindir" 2>/dev/null || true
[ -w "$bindir" ] || fail "cannot write to $bindir; run as root, or choose a directory with -b"
# Written beside the target and renamed over it: a running vmsctl, a full
# disk or an interrupted copy never leaves a truncated binary behind.
new=$(mktemp "$bindir/.$name.XXXXXX") || fail "cannot write to $bindir"
trap 'rm -rf "$tmp" "$new"' EXIT
{ cp "$tmp/$name" "$new" && chmod 0755 "$new" && mv -f "$new" "$bindir/$name"; } ||
	fail "could not install into $bindir"
installed=$("$bindir/$name" version) || fail "the installed $bindir/$name does not run (a noexec mount, or a build for another system?)"
say "installed $(printf '%s\n' "$installed" | head -n 1) to $bindir/$name"

# An older install left a hostlint binary that would keep running the old release: point it at the new one, so
# units, cron entries and CI that still say hostlint keep working for now (it says it is deprecated).
# Only a file that says it is hostlint is replaced: not a directory, not something else of that name.
if [ "$name" = vmsctl ] && [ -f "$bindir/hostlint" ] && "$bindir/hostlint" version 2>/dev/null | head -n 1 | grep -q '^hostlint v'; then
	ln -sf vmsctl "$bindir/hostlint" && say "replaced the old $bindir/hostlint with a link to vmsctl: it will go away in a later release"
fi
