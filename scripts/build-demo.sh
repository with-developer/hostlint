#!/bin/sh
# Builds the static live demo into site/demo (published by .github/workflows/pages.yml): the dashboard built with `--mode demo`, and
# the answers of `vmsctl server demo` recorded into demo-data.json next to it. Needs ./vmsctl (make build), node 22 and npm.
set -eu
cd "$(dirname "$0")/.."
bin=${VMSCTL:-./vmsctl}
port=${DEMO_PORT:-18943}
log=$(mktemp)
"$bin" server demo --listen "127.0.0.1:$port" >"$log" 2>&1 &
pid=$!
trap 'kill $pid 2>/dev/null || true; rm -f "$log"' EXIT INT TERM
i=0
while ! grep -q 'hlt_api_' "$log"; do
	if ! kill -0 "$pid" 2>/dev/null; then
		cat "$log" >&2
		echo "the demo server stopped" >&2
		exit 1
	fi
	sleep 0.5
	i=$((i + 1))
	if [ "$i" -ge 60 ]; then
		cat "$log" >&2
		echo "the demo server did not start" >&2
		exit 1
	fi
done
token=$(grep -o 'hlt_api_[A-Za-z0-9_-]*' "$log" | head -1)
(cd web && npm ci --no-audit --no-fund >/dev/null && npm run build:demo)
node web/scripts/record-demo.mjs "http://127.0.0.1:$port" "$token" site/demo/demo-data.json
