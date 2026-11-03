# Contributing to hostlint

Thanks for helping. This page explains how the project is put together and what a change needs
before it is merged. Design decisions live in [docs/adr](docs/adr/); please read the
[vision](docs/VISION.md) first — its principles are not up for negotiation in a pull request.

## Ground rules

- **No false PASS.** If a check cannot decide, it reports `ERROR` or `MANUAL`. Every check has a
  test case where its input is absent, unavailable or incomplete, and that case must not pass.
- **Observation only.** Code never changes the scanned host. Only collectors touch the host, and
  only through `internal/hostfs`; commands come from a fixed list with fixed arguments. Lint rules
  enforce this (`make lint`).
- **Secrets never become facts.** Collectors expose derived values (the hash algorithm, not the
  hash).
- **Clean-room content.** Write titles, descriptions and guidance in your own words. Never copy
  text from CIS Benchmarks or the KISA guide; reference control IDs only.

## Getting started

```sh
git clone https://github.com/with-developer/hostlint
cd hostlint
make test   # unit tests with the race detector
make lint   # golangci-lint, the ADR 0004 lint guards and go.mod tidiness
make build  # ./hostlint
```

Linux-only code (`*_linux.go`) is tested in CI, or locally in Docker:

```sh
docker run --rm -v "$PWD":/src:ro -w /src -e GOCACHE=/tmp/gc golang:1.27 go test ./...
```

## How a check is built

1. A **collector** (`internal/collect`) reads the host and returns typed **facts**, for example
   `pam.lockout.login.enforced` or `services.started`. Collectors decide what files mean the way
   the program that reads them does, and say when what they saw is incomplete.
2. A **check** (`rules/<area>/<name>.yaml`) compares facts with what is expected, in one of five
   kinds: `setting`, `file`, `violations`, `expect` (a CEL expression) or `manual`.
3. A **profile** (`profiles/<id>.yaml`) maps a standard's controls to checks.

### Writing a check

```yaml
id: services.no-telnet
version: 1
title: Telnet is not started
severity: medium
description: Lists the ways the telnet service is started.
rationale: Telnet sends passwords and sessions in clear text.
remediation: Disable telnet and use SSH.
violations:
  over: services.started
  as: s
  where: s.service in ["telnet", "telnetd"] || s.program.matches("/(in\\.)?telnetd$")
  key: s.kind + ":" + s.name
  text: s.name + " (" + s.kind + ") at " + s.source
  allow_empty: true
tests:
  - name: not started
    facts:
      services: {started: []}
    want: PASS
  - name: started
    facts:
      services: {started: [{service: telnet, name: telnet.socket, kind: unit, source: "/etc/systemd/system/sockets.target.wants/telnet.socket"}]}
    want: FAIL
  - name: running units unknown
    input: incomplete
    incomplete: [services]
    facts:
      services: {started: []}
    want: ERROR
```

`go test ./rules` loads every rule, type-checks its expressions against the facts and runs its
tests. Each automated check needs a `PASS` case, a `FAIL` case and an absent, unavailable or
incomplete case that does not pass. The fact documents in tests are validated against the fact
types, so a misspelled field is an error.

### Writing a collector

- Read the host only through `hostfs` (`h.FS`, `h.Runner`), honor the context, and stay within
  the collector timeout.
- Test it with **fixtures captured from real distributions** (`internal/collect/testdata/`), and
  cover malformed, missing and unreadable input.
- When something cannot be read, return incomplete facts (`Complete: false` with `Skipped`), or
  mark the affected field `Unknown` or `Partial` — never an empty list that would make a check
  pass.

## Pull requests

- One logical change per pull request, with tests. Conventional Commits (`feat:`, `fix:`,
  `docs:`, …) in the imperative mood.
- Code, comments, commits and issues are in English. User-facing documents (README, guides) have
  a Korean translation next to them (`*.ko.md`), updated in the same pull request.
- New dependencies need a reason in the pull request; the standard library is preferred.
- `make test lint` must pass; CI runs the same plus builds for linux/amd64 and linux/arm64 and
  govulncheck.

## Reporting bugs and security issues

Open an issue with the distribution, the hostlint version and, if you can, the facts or files
involved. For anything that could be a vulnerability, follow [SECURITY.md](SECURITY.md) instead.
