# 0006. Rule format, evaluation and result schema

- Status: Accepted
- Date: 2026-11-02

## Context

ADR 0003 split *checks* (standard-agnostic, stable IDs) from *control mappings* (versioned
overlays per standard). ADR 0004 says rules are data that cannot execute, collectors are the
only code touching the host, and results never leak secrets. This ADR fixes the concrete format:
how a check is written, how it is evaluated, how results roll up into controls, and the JSON
document every output — and later the fleet server — consumes.

Requirements, in priority order:

1. **No false PASS.** Missing data, partial observation, parse failures, timeouts and weakened
   configuration must never surface as `PASS` (or as a `NOT_APPLICABLE` that lets a control pass).
2. **Explainable.** Every result says what was observed and where (file and line when known).
3. **Safe by construction.** A rule cannot run anything, loop forever or reach a secret.
4. **Easy to contribute.** Adding a check is one YAML file with its own tests; no Go for the
   common case.
5. **Validated before release.** Broken rules fail CI, not users.

## Decision

### 1. Two phases: collect, then evaluate

A scan first runs the **collectors** the selected checks need, then **evaluates** checks as
pure functions of the collected facts. Collectors are Go (ADR 0004): all I/O goes through
`internal/hostfs`, each has a timeout, and evaluation does no I/O at all.

### 2. Facts

Each collector exposes one top-level variable (`sshd`, `accounts`, `shadow`, `pam`,
`login_defs`, `sysctl`, `packages`, `services`, `os`, …). Facts are Go structs and are the public
contract for rule authors; the fact reference is generated from them.

- **Field types are restricted** to `string`, `int64`, `bool`, lists, string-keyed maps and
  nested structs — no pointers, unsigned integers or `time.Time`. (CEL reads a nil pointer as a
  zero value and treats zero as "unset"; `uint` against an `int` literal fails type checks.)
  A reflection test enforces this.
- **Configuration values are `Setting`s:** `{value, explicit, source}` — the effective value
  as text, whether it came from a file rather than a default, and its provenance
  (`/etc/login.defs:25`, `default (OpenSSH 9.6)`, `sshd -T`). Settings live in maps keyed by
  the normalized key, and a setting is in one of three states:
  - **explicit** — set in a file;
  - **default** — not set, and the default is known for the installed software version;
  - **unknown** — not set and no default is known: the key is **absent from the map**, so an
    expression reading it fails (→ `ERROR`) unless it handles absence (`has()`, `?.`).

  Collectors do not reinterpret values: `PASS_MAX_DAYS -1` stays `-1`. Deciding that `-1`
  means "no limit" is the check's job, done with closed ranges (§3).
- **Defaults are keyed by software version** (e.g. the OpenSSH version), cited, and tested. An
  unknown version means no default.
- **Completeness is explicit.** Every collector result carries `complete` and `skipped`
  ("walk stopped at 2,000,000 entries", "cannot read /var/spool/cron: permission denied").
  `internal/hostfs` provides its own glob and walk that report errors — never Go's
  `filepath.Glob`, which silently drops unreadable directories.
- **Secrets are not facts.** Password hashes, private keys and community strings never appear
  in any fact; collectors expose derived, non-secret values instead (the hashing algorithm
  `sha512`, "community string is a well-known default").
- **Live vs. filesystem.** Each collector declares whether it observes the running system
  (`/proc`, sockets, processes, `sshd -T`, systemd state) or only files. Under `--root`, live
  collectors are *unavailable*; hostlint never runs the target's binaries.
- **Presence** of a service is detected from several signals (package, binary, unit, listening
  socket), so software installed outside the package manager is not missed.

### 3. Checks

One check per file under `rules/<area>/<name>.yaml`. The ID is `<area>.<name>`, must match the
path, and is permanent. YAML conventions: expressions are block scalars (`>-`), modes are quoted
strings.

```yaml
id: ssh.permit-root-login
version: 1                   # bump when the meaning changes
title: SSH does not allow direct root login
title_ko: SSH root 직접 로그인 차단
severity: high               # low | medium | high
description: Checks the global effective PermitRootLogin of the OpenSSH server.
rationale: Direct root login removes accountability and exposes the most powerful account.
remediation: Set `PermitRootLogin no` in /etc/ssh/sshd_config and reload sshd.
platforms: [debian, rhel]    # optional; OS families from a closed list
applies: >-                  # optional CEL; false → NOT_APPLICABLE, with the evidence shown
  sshd.present
setting:
  fact: sshd.config.permitrootlogin
  in: ["no"]
  absent: default            # compare the version's default (prohibit-password → FAIL)
```

Overrides in `Match` blocks are separate facts (`sshd.match`), checked by a companion
`violations` check; the U-01 mapping lists both.

`platforms` takes OS families — `debian` (Debian, Ubuntu) and `rhel` (RHEL, CentOS, Rocky
Linux, AlmaLinux) — and unknown names fail validation. Version-specific logic goes in `applies`
(`os.version_major >= 8`).

A check has exactly one of five **kinds**:

| Kind | Shape | Result |
|---|---|---|
| `setting` | a `Setting` fact; `in` (allowlist), `range` (`min`/`max`, integers, both required) or `matches` (RE2, full match); `absent: fail \| error \| default` | `PASS`/`FAIL` with the value, its state and source |
| `file` | `paths`, `owner`, `group`, `mode` (maximum), `missing`, `no_match` | `PASS`/`FAIL` per path |
| `violations` | `over` (a fact path: the population), `as`, `where` (CEL bool), `key`, `text` (CEL string) | `PASS` if no element matches; `FAIL` lists the matches |
| `expect` | CEL bool without comprehensions | `PASS` if true, else `FAIL` |
| `manual` | `guidance`, `show` (CEL) | `MANUAL`, with the evidence to review |

**`setting`:** `absent` applies when the value is not explicit — `fail` → `FAIL`, `error` →
`ERROR`, `default` → compare the known default, or `ERROR` if it is unknown. Allowlists and
closed ranges are required instead of negations: `range: {min: 1, max: 90}` rejects the `-1`
that `<= 90` would accept.

**`violations`:**

```yaml
violations:
  over: accounts.users       # coverage: "checked 37 accounts"
  as: u
  where: u.uid == 0 && u.name != "root"
  key: u.name                # stable identity for diffs between scans
  text: '"UID 0 assigned to " + u.name'
```

An empty population is `ERROR` unless the check sets `allow_empty: true`. If `where` errors on
an element, the result is `ERROR` — unless another element matched, in which case the `FAIL`
stands.

**`file`:**

```yaml
file:
  paths: [/etc/passwd]       # literal paths or globs
  owner: [root]
  group: [root]              # optional
  mode: "0644"               # maximum: no permission or special bits beyond these
  missing: error             # required: pass | fail | not_applicable | error
  no_match: error            # required when paths contain a glob
```

Only "does not exist" counts as missing; any other error (e.g. permission denied) is `ERROR`.

**Expressions are CEL** (`cel.dev/cel-go`): side-effect free, not Turing complete,
type-checked against the fact types at load time, with a runtime cost limit and context
cancellation. Rules get the standard macros, the strings, lists, sets and math extensions, and
optional types; any custom function is pure Go written by us. Comprehensions belong in
`violations`, where their results become evidence; `expect` is kept to comparisons and boolean
logic so its evidence can be extracted reliably.

Rules never name commands or pass arguments to them. Paths in `file` checks are read through
`internal/hostfs`, so the sensitive-path denylist applies, and only metadata is read.

### 4. Parameters

A check may declare typed parameters, visible to expressions and bounds as `params.<name>`:

```yaml
params:
  max_days: {type: int, default: 90, stricter: lower, description: Maximum password age in days}
setting:
  fact: login_defs.settings.PASS_MAX_DAYS
  range: {min: 1, max: params.max_days}
  absent: fail
```

Precedence: `hostlint.yaml` > profile > check default. An override may only make a check
**stricter** than the profile (`stricter: lower | higher` for integers); a weaker value is
rejected at load time with a pointer to waivers. Results evaluated with non-default parameters
are marked `customized` and record the effective values. So a profile `PASS` always means at
least the profile's own thresholds.

### 5. Evaluation

The status set is closed for schema v1: `PASS`, `FAIL`, `MANUAL`, `NOT_APPLICABLE`, `ERROR`,
`WAIVED`. Every result other than `PASS` and `FAIL` carries a `reason`.

For each check:

1. **Platform.** OS family unrecognised → `ERROR`. Family not listed → `NOT_APPLICABLE`.
2. **Partial evaluation.** `applies` and the check are evaluated with every failed, unavailable
   or incomplete collector bound to a CEL *unknown*.
   - `applies` unknown or erroring → `ERROR`; false → `NOT_APPLICABLE`.
   - A determined result stands — an alternative that does not matter (`rsyslog` vs.
     `journald`) does not poison it.
   - Undetermined because a collector failed or is unavailable → `ERROR` with its error.
   - Undetermined because a collector is incomplete → evaluated again on the partial data:
     a `violations` or `file` `FAIL` stands (the offending items exist); anything else is
     `ERROR` ("incomplete observation: …"). **Partial data can fail, never pass.**
   - A CEL error (missing key, cost limit) → `ERROR`.
3. **Attestations** apply to `MANUAL` results only (§6).
4. **Waivers** apply last (§6).

### 6. Waivers and attestations

Both live in `hostlint.yaml` (format in #12); both require a reason and an expiry.

- A **waiver** turns `FAIL` or `MANUAL` into `WAIVED`, keeping `originalStatus`. It covers
  `ERROR` only if it says `errors: true` — a deliberate decision that a check cannot run here.
  This replaces "disabling" a check: waived checks are still evaluated, so the observation is
  never lost. Expired waivers stop applying and are listed.
- A **control-level waiver** records the profile revision. It does not apply while any of the
  control's checks is `ERROR`, and it goes stale when the revision changes, so checks added
  later are not silently covered.
- An **attestation** is a human verdict (`PASS` or `FAIL`, who, when) for a `MANUAL` check,
  bound to the check's logic digest and to a digest of the full, canonical `show` value (not
  the truncated evidence). It applies only while both digests match and the `show` evidence is
  complete; the result records `statusSource: attested`. A manual check with nothing to `show`
  can only be attested until the attestation expires.

### 7. Profiles and control aggregation

`profiles/<id>.yaml` maps a standard edition's controls to checks:

```yaml
id: kisa-2026
revision: 1                  # bump on any mapping change
title: KISA CII technical vulnerability assessment guide, 2026 edition — Unix servers
controls:
  - id: U-01
    title: Restrict remote root login
    title_ko: root 원격 접속 제한
    severity: high
    checks: [ssh.permit-root-login, ssh.match-permit-root-login, telnet.root-login]
  - id: U-64
    title: Apply security patches and vendor advisories
    severity: high
    manual: Review the patch policy and the latest vendor advisories.
```

A control's status is the highest-precedence status among its checks:

`FAIL` > `ERROR` > `MANUAL` > `WAIVED` > `PASS` > `NOT_APPLICABLE`

A control passes only if every applicable check passes (ADR 0003); "A or B is acceptable" is
written inside one check. A control with no checks is `MANUAL`. `--fail-on` uses control
severity.

Convention for absent services: a check phrased "X is disabled" passes when X is absent, with
that as evidence; a check phrased "X is configured securely" is `NOT_APPLICABLE` when X is
absent.

### 8. Evidence

Evidence is a sorted list of items `{key, text, source}`. The `key` is stable (fact path or the
`violations` key) so later scans can be diffed. Evidence is bounded in count and length, and
never contains secrets.

- `setting`: the value, its state (explicit / default) and source.
- `file`: one item per offending path ("mode 0664 exceeds 0644").
- `violations`: one item per match, plus `coverage` (population and count).
- `expect`: the values of the fact paths the expression references, from CEL's evaluation
  state, with provenance from the collector's path table. A check may add `failure:`, a sentence
  shown first when it fails, where those values alone do not say what is wrong.
- `manual`: the guidance and the values of `show`.
- `NOT_APPLICABLE` and `ERROR`: the deciding facts or the error.

### 9. Tests

- **Checks** are tested against **fact documents** in the rule file, strictly validated against
  the fact schema (unknown fields are errors). A test can mark collectors `incomplete` or
  `unavailable`. Each automated check needs at least one `PASS` case, one `FAIL` case, and one
  case where its input is absent, unavailable or incomplete that must **not** `PASS`. CI
  enforces this.
- **Collectors** are tested against fixture files captured from real distributions (the
  container matrix, #13), including malformed, missing and unreadable inputs.
- End-to-end golden results (#13) test collectors and checks together.

### 10. Versioning and identity

- Each check result records the check `version` and a `digest` of its logic (kind, expressions,
  params, platforms) — not its prose — so results are comparable exactly when digests match,
  and fixing a translation changes nothing.
- Each profile records `revision` and a digest; the profile ID carries the edition.
- A check result's `ref` is its ID, plus a parameter digest when parameters differ from the
  check's defaults (`accounts.password-max-age#3f9a1c2e`). Controls reference check results by
  `ref`, so one scan can later evaluate a check under several profiles without a schema change.
- Fact fields are versioned with the tool; external rule packs (later) will declare the minimum
  hostlint version they need.

### 11. Result document v1

JSON, `"schemaVersion": 1`, specified by `schema/result-v1.schema.json`. Additive changes (new
optional fields) stay in v1 and consumers must ignore unknown fields. The status enum is closed:
a new status requires `schemaVersion: 2`. `hostlint report` keeps reading every version it ever
wrote.

```json
{
  "schemaVersion": 1,
  "scan": {
    "id": "019a43c2-6f0e-7b51-9b5f-3c2e8d1a4f10",
    "startedAt": "2026-11-02T12:00:00Z",
    "finishedAt": "2026-11-02T12:00:03Z",
    "tool": {"name": "hostlint", "version": "v0.1.0", "commit": "59aea71"},
    "target": {"kind": "host", "root": "/"},
    "privileges": {"euid": 0, "capabilities": ["CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH"]}
  },
  "host": {
    "hostname": "web-01",
    "hostId": "6d1f…",
    "os": {"id": "ubuntu", "versionId": "24.04", "family": "debian",
           "name": "Ubuntu 24.04.1 LTS", "supported": true},
    "kernel": "6.8.0-45-generic",
    "arch": "amd64",
    "labels": {"env": "prod"}
  },
  "profiles": [{"id": "kisa-2026", "revision": 1, "digest": "sha256:…"}],
  "summary": {
    "kisa-2026": {
      "controls": {"PASS": 44, "FAIL": 9, "MANUAL": 7, "NOT_APPLICABLE": 5, "ERROR": 1, "WAIVED": 1},
      "customized": 0
    }
  },
  "controls": [
    {"profile": "kisa-2026", "id": "U-01", "title": "Restrict remote root login",
     "titleKo": "root 원격 접속 제한", "severity": "high", "status": "FAIL",
     "checks": ["ssh.permit-root-login", "ssh.match-permit-root-login", "telnet.root-login"]}
  ],
  "checks": [
    {"ref": "ssh.permit-root-login", "id": "ssh.permit-root-login", "version": 1,
     "digest": "sha256:…", "title": "SSH does not allow direct root login",
     "severity": "high", "status": "FAIL", "statusSource": "observed",
     "evidence": [{"key": "sshd.config.permitrootlogin",
                   "text": "PermitRootLogin is \"yes\" (explicit)",
                   "source": "/etc/ssh/sshd_config:32"}]},
    {"ref": "accounts.password-max-age#3f9a1c2e", "id": "accounts.password-max-age",
     "version": 1, "digest": "sha256:…", "title": "Passwords expire",
     "severity": "medium", "status": "WAIVED", "originalStatus": "FAIL",
     "reason": "waived until 2027-03-31: legacy batch accounts, ticket OPS-1182",
     "statusSource": "observed", "params": {"max_days": 60}, "customized": true,
     "evidence": [{"key": "login_defs.settings.PASS_MAX_DAYS",
                   "text": "PASS_MAX_DAYS is 99999 (explicit)", "source": "/etc/login.defs:165"}],
     "waiver": {"reason": "legacy batch accounts, ticket OPS-1182", "expires": "2027-03-31",
                "scope": "check"}}
  ],
  "collectors": [
    {"name": "sshd", "version": 1, "access": "live", "status": "ok", "complete": true,
     "durationMs": 4},
    {"name": "fs_walk", "version": 1, "access": "filesystem", "status": "ok", "complete": false,
     "skipped": ["/srv/data: permission denied"], "durationMs": 8120}
  ]
}
```

A complete document that validates against the schema is in
`schema/result-v1.example.json`.

- `scan.id` is a UUIDv7. `host.hostId` is an HMAC-SHA256 of `/etc/machine-id` under a fixed
  hostlint key, so the raw machine ID never leaves the host. Cloned machines can share a
  machine ID, so consumers identify hosts by several signals (hostId, hostname, labels), and
  `hostlint report` never silently merges two input files into one host.
- `host.os.supported` says whether this OS version is in the tested matrix; other versions of a
  known family are scanned best-effort and reports say so.
- `target.kind` is `host` or `root`; for `root`, live facts (kernel, sockets) are absent.
- `privileges` records the effective UID and the capabilities that matter for reading files;
  unprivileged scans produce more `ERROR`s, and reports say why.
- `summary.*.customized` counts results evaluated with stricter local parameters; they are also
  counted under their status.
- Arrays are emitted in a deterministic order.

### 12. Limits

Collectors run with a default timeout of 30 s; filesystem walks have entry, depth and time
budgets (configurable) and report themselves incomplete, never silently short, when they hit
one. The stripped `linux/amd64` binary stays under 30 MB and CI reports its size. (Measured
while deciding: 4.8 MB today; CEL adds about 8 MB.)

## Consequences

- New dependency `cel.dev/cel-go` (with ANTLR and protobuf runtimes), accepted for sandboxing,
  load-time type checking, cost limits and partial evaluation that we would otherwise build.
- Five check kinds instead of one: the common cases (`setting`, `file`) need no expression and
  give exact evidence; CEL is for lists and boolean logic.
- Collectors carry real complexity — effective values, provenance, completeness, and defaults
  that vary by software version — because that is where false results come from.
- More `ERROR`s than a naive scanner, especially unprivileged or under `--root`. That is the
  price of never guessing; reports must explain each one.
- Checks are tested on facts and collectors on captured files: two kinds of fixtures, but each
  stays small, and a collector change does not rewrite every rule test.

## Alternatives considered

- **Structured operators only:** account, PAM and filesystem checks need filters and boolean
  logic, which grows into an ad-hoc language. Kept for the common cases as `setting` and `file`.
- **expr-lang/expr:** lighter, but a missing map key yields a zero value (a false-PASS path) and
  Go methods on facts are callable by default.
- **Rego (OPA):** powerful but heavy and hard for sysadmins to read.
- **Checks in Go:** contributors need Go, and policy packs become impossible without
  recompiling.
- **Running real collectors in rule tests:** couples every rule test to collector internals
  (exact command lines, distribution file layouts).
- **Shell snippets (Lynis, the original VMS):** violates ADR 0004.

## Review

Two rounds of opposing-view review (2026-11-02, built-in agent, reading the cel-go source).

- **Round 1** kept CEL but found three false-PASS paths in the first draft: documented
  defaults such as `PASS_MAX_DAYS -1` passing an unbounded `<=`; partial observations
  (unreadable globs, truncated walks, live facts under `--root`) yielding empty violation lists;
  and configuration (disabled checks, weakened parameters, unrecognised OS) producing `PASS` or
  `NOT_APPLICABLE`. Answered by three-state `Setting`s with closed ranges, completeness
  tracking, the `setting` kind, stricter-only parameters and `ERROR` for unknown platforms.
  It also led to testing checks against fact documents, attestations, per-check digests, and
  the fleet-oriented result fields.
- **Round 2** found that `NOT_APPLICABLE` and attested results could still bypass the
  incompleteness rule, that customized parameters could still yield a misleading `PASS`, and
  that "disabled" checks lost their observation. Answered by evaluating everything with
  unknowns (`applies` unknown → `ERROR`), stricter-only overrides, waivers replacing
  disabling, full-value attestation digests, control waivers that never hide `ERROR`, and the
  `violations` `key`.
