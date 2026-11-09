#!/usr/bin/env bash
# Proves the ADR 0004 lint guards in .golangci.yml fire.
#
# internal/lintguard holds deliberate violations, built only with the
# `lintguard` tag. Every line marked `// want <linter>` must be reported by
# exactly that linter, and no other line may be reported.
#
# Usage: scripts/lint-guards.sh <golangci-lint binary>
set -euo pipefail

lint=${1:?usage: $0 <golangci-lint binary>}
dir=internal/lintguard

want=$(grep -Hn '// want ' "$dir"/*.go \
  | sed -E 's#^([^:]+):([0-9]+):.*// want ([a-z]+).*#\1:\2 \3#' | sort)

got=$("$lint" run --build-tags lintguard --max-issues-per-linter 0 --max-same-issues 0 \
  --output.text.colors=false --show-stats=false "./$dir/..." 2>/dev/null \
  | sed -nE 's#^([^:]+):([0-9]+):([0-9]+:)? .*\(([a-z]+)\)$#\1:\2 \4#p' | sort || true)

if [[ "$want" != "$got" ]]; then
  echo "lint guards: reported issues differ from the // want markers" >&2
  diff <(echo "$want") <(echo "$got") >&2 || true
  exit 1
fi
# The depguard entries that keep the scanning packages away from the server and the push client name import paths. A
# path that stopped matching (a renamed module, a moved package) would deny nothing and still pass, so check that
# each one is the module's own path of a package that exists.
mod=$(go list -m)
for pkg in internal/server internal/push; do
  grep -qE "^[[:space:]]+- pkg: ${mod//./\\.}/$pkg\$" .golangci.yml || { echo "lint guards: .golangci.yml has no depguard entry for $mod/$pkg" >&2; exit 1; }
  [[ -d $pkg ]] || { echo "lint guards: $pkg does not exist" >&2; exit 1; }
done

echo "lint guards: $(echo "$want" | wc -l | tr -d ' ') violations reported as expected"
