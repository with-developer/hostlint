# CLAUDE.md

Guidance for AI coding agents and human contributors working on hostlint.

## Start here

- Product direction: [docs/VISION.md](docs/VISION.md) — what we build, for whom, principles, non-goals.
- Decisions already made: [docs/adr/](docs/adr/) — don't relitigate; supersede with a new ADR.
- Plan: [docs/ROADMAP.md](docs/ROADMAP.md), plus GitHub milestones and issues.

## Status

Pre-v0.1. The layout below is the target; keep this file in sync as code lands.

## Commands

- `make build` — `./hostlint` for the current platform (a static binary on Linux);
  cross-compile with `GOOS=linux GOARCH=arm64 make build`
- `make test` — unit tests with the race detector
- `make lint` — golangci-lint for linux (formatting, plus rules that enforce ADR 0004: no exec,
  raw syscalls, host writes or direct host reads outside `internal/hostfs`), `make lint-guards`
  (proves those rules fire, using `internal/lintguard`), and a `go.mod` tidiness check. Builds the
  pinned linter into `.tools/` on first run
- `make fmt` — format the code
- `make vuln` — govulncheck
- `make e2e` — container end-to-end tests (Docker; arrives with #13)

CI runs test, lint, build (linux amd64/arm64) and vuln. `ci-ok` is the required check on `main`.

## Layout (target)

| Path | Purpose |
|---|---|
| `cmd/hostlint/` | Binary entrypoint (signals, exit code) |
| `internal/cli/` | Command definitions (Cobra) |
| `internal/version/` | Build information |
| `internal/engine/` | Rule loading, evaluation, result model |
| `internal/collect/` | Fact collectors — the only code that touches the host |
| `internal/hostfs/` | Rooted filesystem and fixed-argv command runner (testability, `--root`) |
| `internal/output/` | Terminal, JSON, SARIF, JUnit and HTML output |
| `rules/` | Built-in checks (YAML), embedded in the binary |
| `profiles/` | Versioned control mappings per standard (e.g. `kisa-2021`), embedded |
| `testdata/` | Fixture root filesystems per distro (hardened and default) |

## Security invariants — never violate

1. **Read-only.** No code path writes to, or changes the state of, the scanned host.
2. **Rules can't execute.** Only collectors (Go code) run commands, with a fixed argv — no shell,
   no rule-supplied arguments.
3. **No secrets out.** Facts, evidence, logs and errors never contain password hashes, private
   keys or tokens.
4. **Denylist.** Generic file reads go through the sensitive-path denylist in `internal/hostfs`.
5. **No false PASS.** If a control can't be decided reliably, report `MANUAL` or `ERROR` —
   never guess `PASS`.

Changes in these areas need an extra review pass and tests that prove the invariant holds.
See [ADR 0004](docs/adr/0004-observation-only.md).

## Conventions

- **Go:** `gofmt` and `golangci-lint` clean; table-driven tests; no global mutable state;
  collectors take a `context.Context` and are time-bounded.
- **Tests:** every collector has fixture tests; every check has at least one PASS and one FAIL
  fixture.
- **Content:** rule titles and descriptions are written by us. Never copy text from CIS
  Benchmarks (CC BY-NC-SA 4.0) or the KISA guide; reference control IDs only.
- **Language:** code, comments, commits, PRs and issues in English. English docs are the source
  of truth. User-facing docs (README, usage guides, the KISA profile guide) also get a Korean
  translation next to them as `<name>.ko.md`, updated in the same PR; each translation starts
  with `<!-- translated from <file> @ <commit> -->`. Design docs (VISION, ROADMAP, ADRs,
  CONTRIBUTING, this file) are English only. Rule titles may carry Korean translations.
- **Commits:** Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`,
  `ci:`), imperative mood. One logical change per PR.
- **Dependencies:** prefer the standard library; justify every new module in the PR description.
