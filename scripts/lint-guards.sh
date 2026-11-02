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
echo "lint guards: $(echo "$want" | wc -l | tr -d ' ') violations reported as expected"
