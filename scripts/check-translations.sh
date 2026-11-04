#!/bin/sh
# Fails when a pull request changes an English user doc that has a Korean
# translation (NAME.ko.md next to NAME.md) without changing the translation.
# Reads the changed file names, one per line, from standard input; CI feeds it
# the files of the pull request.
set -eu

changed=$(cat)
status=0
for ko in $(git ls-files '*.ko.md'); do
	en="${ko%.ko.md}.md"
	[ -f "$en" ] || continue
	if printf '%s\n' "$changed" | grep -qxF "$en" && ! printf '%s\n' "$changed" | grep -qxF "$ko"; then
		echo "$en changed but $ko did not: update the Korean translation (and its \"translated from\" commit) in the same pull request" >&2
		status=1
	fi
done
exit $status
