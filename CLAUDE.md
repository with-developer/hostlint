# CLAUDE.md

Guidance for AI coding agents and human contributors working on vmsctl.

## Start here

- Product direction: [docs/VISION.md](docs/VISION.md) — what we build, for whom, principles, non-goals.
- Decisions already made: [docs/adr/](docs/adr/) — don't relitigate; supersede with a new ADR.
- Plan: [docs/ROADMAP.md](docs/ROADMAP.md), plus GitHub milestones and issues.

## Status

Released (see [docs/ROADMAP.md](docs/ROADMAP.md) for what each version added). Keep this file in sync as code lands.

## Commands

- `make build` — `./vmsctl` for the current platform (a static binary on Linux);
  cross-compile with `GOOS=linux GOARCH=arm64 make build`
- `make web` — build the dashboard (`web/`, Node 22) into `internal/server/webdist`; `make build-web` builds
  `./vmsctl` with it embedded (`-tags web`, what a release has)
- `make demo-site` — the static live demo into `site/demo` (the dashboard built with `--mode demo`, reading the recorded answers of
  `vmsctl server demo`); CI builds it, and the Pages workflow publishes it. Never committed
- `make test` — unit tests with the race detector
- `make lint` — golangci-lint for linux/amd64 (formatting, plus rules that enforce ADR 0004: no exec,
  raw syscalls, host writes or direct host reads outside `internal/hostfs`), `make lint-guards`
  (proves those rules fire, using `internal/lintguard`), and a `go.mod` tidiness check. Builds the
  pinned linter into `.tools/` on first run
- `make fmt` — format the code
- `make docs` — regenerate `docs/rules.md` (the rule reference) and `docs/facts.md` from `rules/`, `profiles/` and the collectors;
  `make test` fails when it is stale
- `make vuln` — govulncheck
- `make snapshot` — build every release artifact into `dist/` without publishing (GoReleaser;
  `SNAPSHOT_SKIP=sign,sbom` without syft); `scripts/check-release.sh dist` checks them.
  Releases: [docs/RELEASING.md](docs/RELEASING.md)
- `make e2e` — scan every supported distribution in Docker, stock and hardened (`e2e/harden.sh`),
  and compare with the goldens in `e2e/testdata`; `E2E_RUN=debian-12 E2E_UPDATE=1` rewrites the goldens of one distribution.

CI runs test, lint, build (linux amd64/arm64), vuln and a release snapshot. `ci-ok` is the
required check on `main`.

## Layout

| Path | Purpose |
|---|---|
| `cmd/vmsctl/` | Binary entrypoint (signals, exit code) |
| `internal/cli/` | Command definitions (Cobra) |
| `internal/version/` | Build information |
| `internal/engine/` | Rule loading, evaluation, result model |
| `internal/collect/` | Fact collectors; they read the host only through `internal/hostfs` |
| `internal/facts/` | Shared fact types (`Setting`, `OS`) and the fact type restrictions |
| `internal/hostfs/` | Rooted filesystem and fixed-argv command runner (testability, `--root`), and the immutable tree of a container image (`ImageFS`) |
| `internal/image/` | Loader of `docker save` and OCI image archives for `scan --image-tar` (untrusted input: strict limits; ADR 0011) |
| `internal/signing/` | Ed25519 signing of results (ADR 0010) |
| `internal/push/` | The client of the fleet server: `scan --push`, `vmsctl agent`; the only package besides `internal/server` that uses `net/http` |
| `internal/server/` | The fleet server: SQLite store and migrations, ingest, read API, sessions, webhook, the agent's jobs (ADR 0010, 0014) |
| `web/` | The dashboard (React and TypeScript), built into `internal/server/webdist` and embedded with `-tags web` |
| `internal/config/` | `vmsctl.yaml`: parameter overrides and waivers, read from the machine running vmsctl (not the scanned host), trust-checked |
| `internal/rulesdoc/` | Renders the rule reference `docs/rules.md` and the fact reference `docs/facts.md` from the built-in rules, profiles and collectors |
| `internal/output/` | Terminal, JSON, SARIF, JUnit and HTML output |
| `rules/` | Built-in checks (YAML), embedded in the binary |
| `profiles/` | Versioned control mappings per standard edition (e.g. `kisa-2026`), embedded |
| `schema/` | JSON Schema of the result document (ADR 0006), with a valid example |
| `testdata/` | Fixture root filesystems per distro (hardened and default) |
| `e2e/` | Docker-based scans of every supported distribution (stock and hardened), image scans, and the golden results |
| `examples/policy-pack/` | An example policy pack (ADR 0012, `docs/packs.md`) |
| `action.yml` | The GitHub Action (composite): installs a verified release and scans an image, an archive or a root |
| `packaging/container/` | The Dockerfile of the release image on ghcr.io (`.github/workflows/container.yml`) |
| `install.sh` | The installer: downloads a release, verifies it, installs the binary |
| `scripts/` | Release checks, the translation check, lint guards and the live demo build (`check-release.sh`, `check-translations.sh`, `lint-guards.sh`, `build-demo.sh`) |
| `site/` | The project page for GitHub Pages (English, and `ko/`, with the generated KISA page `ko/kisa/`) and the live demo `demo/` (built, not committed); published by `.github/workflows/pages.yml` |
| `.goreleaser.yaml` | Release build: archives, packages, SBOMs, checksums and signing (docs/RELEASING.md) |

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
- **Tests:** every collector has fixture tests built from files captured from real distributions
  (ADR 0006 §9), served by `hostfs.MemFS`; every check has PASS, FAIL and absent/incomplete
  cases (ADR 0006). Linux-only
  code (`*_linux.go`) is tested in CI or locally in Docker, e.g. `docker run --rm -v "$PWD":/src:ro
  -w /src -e GOCACHE=/tmp/gc golang:1.27 go test ./...`.
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
