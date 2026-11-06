# 0010. Fleet server and dashboard: push first, agent later

- Status: Accepted (phase 1 implemented; phase 2, the agent, needs its own ADR)
- Date: 2026-11-06

## Context

[ADR 0001](0001-go-single-binary-outbound-agent.md) fixed the direction: Go, one binary, a server
that embeds a React + Vite + shadcn/ui interface and defaults to SQLite, and agents that dial out
over mutual TLS and open no listening port. [VISION](../VISION.md) principle 3 says a server
compromise must not become a fleet compromise.

The standalone CLI already produces what a fleet view needs: a versioned JSON result
([ADR 0006](0006-rule-format-evaluation-results.md)), `hostlint report` (many hosts, one static
page) and `hostlint diff` (what changed between two scans). What is missing is a place where results
accumulate, so that an operator sees the state of every host, its history, and what got worse,
without collecting files by hand. The owner wants that place to be a real dashboard, not only a
listing.

A gRPC agent that receives work from the server is the largest part of ADR 0001 and the one that
needs the most security design (enrollment, certificate rotation, what the server may ask for). It
is not needed to show results.

## Decision

Build fleet mode in two phases. This ADR decides phase 1 and the shape of phase 2.

### Phase 1: the server receives results; hosts push them

- `hostlint server` — one process: HTTPS listener, REST API, embedded web UI, SQLite storage.
- `hostlint push FILE` (and `hostlint scan --push URL`) — a host sends a result it produced itself
  to the server with a token. The host decides what it scans and when (cron, a systemd timer,
  CI). **No channel from the server to a host exists in phase 1**: a compromised server cannot run
  anything on a scanned host, which is what principle 3 asks for.
- The server reads a result with the validation of `hostlint report` (`output.ReadResult`: schema
  version, known statuses, resolved references) after its own, tighter limits (below), and treats
  everything in it as untrusted text.

### What push does not protect

The server is an integrity-critical store, not an authority. A compromised server or database can
rewrite stored statuses (FAIL to PASS) and nothing in phase 1 detects it; a stolen ingest token can
submit results for the hosts it may speak for. Phase 1 therefore:

- keeps the raw result of every scan unchanged next to the derived rows, and records every ingest
  (token, source address, scan ID, digest of the document) in an append-only audit table whose rows
  chain a hash of the previous row, so tampering with history is detectable by anyone who kept a
  copy of the latest hash (the server shows it; `hostlint server verify` checks the chain);
- reserves a `signature` field for results and a `credential` kind for keys, and lists **signed
  results** (a per-host Ed25519 key registered at the first push, results signed by `hostlint
  scan --sign-key`) as the first item after phase 1. Until then the documentation says that the
  dashboard is not evidence against a compromised server.

### Tokens that lie

Host name, host ID, labels, `scan.id` and `startedAt` are asserted by the sender. The server:

- orders scans by **its own receive time**; `startedAt` is displayed but not trusted, and a result
  whose `startedAt` is more than five minutes in the future, or older than the host's latest scan
  by more than the retention window, is rejected;
- keeps `(host, scan.id)` unique, so a captured result cannot be replayed;
- binds an ingest token to **one host identity** by default (name and host ID, pinned at first use);
  a token for a set of labels is an explicit opt-in. A second token claiming a known name, or a host
  ID that changes, raises an alert and is not merged;
- shows WAIVED and "customized" counts next to every score, so a result that waives everything is
  visible.

### Limits

A result is rejected above 2 MiB (a full scan of a stock Debian 12 host is 125 KiB; configurable), more than 500
controls or 5000 checks, or strings above 4 KiB; each token has a rate limit and a daily quota, and
rejected documents are logged with the token ID. Titles and descriptions are shown from the
server's own embedded rules by ID when the profile revision is known, and from the result, as plain
text, otherwise.

### Storage

SQLite through a pure-Go driver (`modernc.org/sqlite`, no cgo, so the binary stays static, at a cost
of several MB of binary size), one file in WAL mode.

- `hosts` (internal ID, display name), `host_identities` (name, host ID, first and last seen),
  `credentials` (kind: `token` now, `key` or `certificate` later; bound to a host or a label set;
  hash, prefix, created, last used, expires, revoked), `scans` (host, receive time, schema version,
  the raw JSON compressed), `scan_controls` (one row per control: status, severity, profile revision),
  `scan_checks` (only checks that are not PASS or NOT_APPLICABLE; the rest can be read from the raw
  JSON), `sessions`, `audit`.
- Size: 500 hosts scanned daily is about 33,000 control rows and a few thousand check rows a day,
  roughly 1 GB a year with the raw documents; one SQLite file handles it.
- Retention is by age (default 400 days, so a yearly audit has its history) with batch deletes;
  **the latest scan of every host is kept forever**.
- Migrations are numbered SQL files embedded in the binary and applied at start; every derived row
  records the result schema version it came from, and a derived table can be rebuilt from the raw
  documents. Backup is a copy of the file (`hostlint server backup` uses SQLite's online backup).
- PostgreSQL stays optional and out of phase 1.

### API

`/api/v1`, JSON, designed API-first so the interface can be replaced. Ingest: `POST /results`
(ingest token). Read (session or a read-only API token, so CI can ask whether the fleet regressed):
hosts, host detail, scans of a host, one scan, `GET /diff?old=&new=` (the code of `hostlint diff`),
overview numbers, host export (CSV and JSON), tokens. Also `/healthz` and Prometheus-style
`/metrics`. The API is marked unstable until a release says otherwise.

### Authentication

- **Tokens** are random with at least 128 bits of entropy, carry a visible prefix (`hlt_ing_`,
  `hlt_api_`) so secret scanners can find a leak, are shown once and stored as a SHA-256 hash,
  compared in constant time; each has a last-used time and an optional expiry and can be revoked.
- **Dashboard**: at first start the server writes a one-time admin token to a file (mode 0600), not
  to the log; login exchanges it for a session (`HttpOnly`, `Secure`, `SameSite=Strict`, idle and
  absolute timeouts) with a CSRF token for writes, and is rate-limited. `hostlint server admin
  reset-token` replaces a lost token. Users, roles and OIDC come later; phase 1 has one role.
- **Transport**: TLS always, from `--tls-cert/--tls-key` or generated and self-signed. `hostlint push
  --pin` pins the **public key** (SPKI), which survives certificate renewal. Plain HTTP is allowed
  only on a loopback address or behind `--behind-proxy`, which trusts forwarded headers only from the
  proxy addresses it is given.

### Dashboard

Built to `web/dist` and embedded with `go:embed`. The release pipeline builds it in a pinned Node
container with `npm ci --ignore-scripts` from a committed lockfile, and the SBOM lists its
dependencies. `go install` builds the server without the interface (`-tags noweb` is the default
for it), which the documentation says. Order of delivery:

1. **Overview** — hosts, hosts with failing controls, regressions in the last 7 days, hosts that did
   not report for N days (stale) or never did; status distribution with WAIVED shown; the controls
   that fail on most hosts; recent regressions and fixes.
2. **Hosts** — filters (label, OS, profile, status, severity), sorting, export.
3. **Host** — control list with evidence (as in the HTML report), a diff against any earlier scan.
4. **Settings** — tokens, retention, alert webhook, server information.

Later, in this order: **Control** (which hosts fail it, since when), **Drift** (timeline of
regressions and fixes), history charts.

**Score.** The number shown per host is `PASS ÷ (PASS + FAIL + ERROR + MANUAL)`: undecided results
count against it, NOT_APPLICABLE and WAIVED are left out of the ratio and displayed beside it, and the
counts of FAIL, ERROR, MANUAL and WAIVED are always on the same card.

**Alerts.** One generic outgoing webhook (JSON) for: a host stale for N days, a regression, a new
host, an identity conflict. A dashboard nobody opens finds nothing.

The interface renders text as text (React escaping, no raw HTML, no markup built from a result) and
ships with `Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self';
img-src 'self'; connect-src 'self'; frame-ancestors 'none'`.

### Out of phase 1

Remote scan triggering and the agent, multi-tenant or role-based access, PostgreSQL, editing waivers
in the UI (waivers stay in `hostlint.yaml` on the host and show in results), e-mail notifications,
host decommissioning beyond deleting a host and its scans.

### Phase 2: the outbound agent (own ADR)

`hostlint agent` keeps a gRPC stream with mutual TLS to the server for scheduled and on-demand
scans, and reuses the ingest path. An agent enrolls once with a token and gets a certificate; its
identity becomes a `credential` of kind `certificate` bound to the same internal host ID, so a
host that pushed before is the same row after it enrolls (matched by the pinned host ID, confirmed
by an operator when names differ).

## Alternatives considered

- **Agent first (ADR 0001 as written).** The strongest design, but weeks before the first dashboard,
  and the hardest part to get right. Phase 1 reaches a usable dashboard sooner and keeps phase 2 open.
- **Server-rendered Go templates and htmx instead of React.** No Node in the build, a smaller supply
  chain, and plausible for a first release of four screens. Not chosen because the dashboard the
  owner asks for (filters, drill-down, history, later charts) is the interactive kind and ADR 0001
  already chose React. Because the API comes first, this choice can be reversed without a data change.
- **Committing the built `web/dist`.** Reproducible Go-only builds, but generated code in the
  repository and in every diff; the pinned container build with a lockfile is the chosen compromise.
- **A hosted service.** Contradicts "boring to install and run" and the self-hoster audience.
- **PostgreSQL only.** Heavier to try; SQLite handles the scale of one fleet's results.

## Consequences

- The release build gains a Node step and a pure-Go SQLite driver (new dependencies, justified in the
  PRs that add them). The CLI keeps working without either: the server is a separate subcommand.
- Hosts need a route to the server and a token; no scanned host opens an inbound port.
- The result document becomes a long-lived interface between hosts and server: a server accepts
  older result schema versions within a major version.
- Until results are signed, the server's records are only as trustworthy as the server.
- Phase 2 adds the agent without changing storage, API or dashboard.

## Open questions

- Subcommands of one binary or a separate `hostlint-server` (ADR 0001 left this for later). Phase 1
  uses subcommands; the binary size after adding SQLite decides whether to split.
- ~~Whether `scan --sign-key` ships in phase 1 or right after.~~ Decided and implemented right after phase 1
  (v0.10): an Ed25519 key per host (`hostlint key generate`), the signature over the raw result
  document (domain-separated) sent in two headers, the public key registered at the host's first signed
  result, later results of that host required to be signed with it, `hostlint server verify`
  re-checking stored scans against their ingest audit rows (the audit hash covers the key fingerprint),
  signed results refused unless newer than the host's latest scan (replay), `host reset-key` for a replaced
  key. The key is trusted on first use: a
  database controlled by an attacker can replace a result with its signature and key, which is why the
  fingerprints and the audit hash are meant to be kept elsewhere.
