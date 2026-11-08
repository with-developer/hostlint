# Roadmap

High-level plan. Day-to-day work is tracked in GitHub milestones and issues; this file changes
only when direction changes (record why in an ADR).

## v0.1 — Standalone CLI

**Goal:** download one binary, run `hostlint scan`, get a trustworthy per-control report.
**Scope:** Ubuntu 22.04/24.04/26.04, Debian 12/13, RHEL-compatible 9/10 (Rocky Linux,
AlmaLinux), Amazon Linux 2023, and CentOS/RHEL 7 (best-effort: past end-of-life, but still common among Korean
compliance targets); KISA CII Unix profile, 2026 edition (U-01–U-67, see ADR 0007). Other
versions of these families are scanned best-effort and marked as such in results. CentOS 6 is
out of reach — Go binaries need Linux 3.2 or later.

Work breakdown — each item becomes an issue in milestone `v0.1.0`:

1. **Scaffold & CI** — Go module, CLI skeleton (`hostlint version`), Makefile, golangci-lint,
   GitHub Actions (test, lint, build, govulncheck), branch protection on `main`.
2. **Design: rule format, evaluation and result schema** (ADR) — rule YAML, expression language,
   collector interface, statuses (`PASS` `FAIL` `MANUAL` `NOT_APPLICABLE` `ERROR` `WAIVED`),
   control aggregation, versioned JSON result schema (host identity, scan ID, rule/profile versions).
3. **Host access layer** — rooted filesystem (`--root`), fixed-argv command runner with recorded
   outputs for tests, OS detection, sensitive-path denylist.
4. **Engine** — load and validate embedded rules/profiles, lazy collectors with timeouts,
   evaluation; failures become `ERROR` results, never crashes.
5. **Collectors: config and accounts** — file metadata, key/value configs, effective sshd config,
   login.defs, PAM/pwquality/faillock (pam_tally2 on EL7), accounts (passwd/group/shadow
   aging — never hashes).
6. **Collectors: packages, services, filesystem** — dpkg/rpm, systemd (degrades gracefully
   without systemd), inetd/xinetd, SUID/SGID, world-writable and unowned files (bounded walks),
   listening sockets.
7. **KISA profile: accounts** — U-01–U-13.
8. **KISA profile: files and directories** — U-14–U-33.
9. **KISA profile: services, patching, logging** — U-34–U-67. Controls that cannot be automated
   are `MANUAL` with guidance.
10. **`hostlint scan` output** — terminal table, JSON, SARIF, JUnit; `--profile`, `--format`,
    `--output`, `--fail-on`, exit codes; golden-file tests.
11. **`hostlint report`** — merge many hosts' JSON into one self-contained HTML report
    (hosts × controls matrix, drill-down, works offline).
12. **Config file** — `hostlint.yaml`: profile selection, stricter parameters, waivers with reason
    and expiry, and attestations.
13. **Container e2e matrix** — Docker-based end-to-end tests per supported distro (including
    `centos:7`) with hardened and default fixtures and golden results, in CI.
14. **Release pipeline** — GoReleaser (linux amd64/arm64), checksums, cosign keyless signing,
    SBOM, .deb/.rpm, install script. The first public release required the owner's approval.
15. **Docs** — README (EN) with a demo GIF, Korean translations of user-facing docs
    (`*.ko.md`), generated rule reference, CONTRIBUTING (how to write a check), SECURITY.md,
    and a CI check that flags English user docs changed without their `.ko.md`.
16. **Landing page** — project site on GitHub Pages (no custom domain without the owner's
    approval).

## Fleet mode

**Phase 1 shipped ([ADR 0010](adr/0010-fleet-server-and-dashboard.md)):** `hostlint server` (SQLite, tokens, a
hash-chained audit table, sessions) with an embedded web dashboard, `hostlint push` and `hostlint scan --push` (hosts
send results; the server has no channel to them), `hostlint diff`, retention, backup, host administration,
`hostlint server demo`, signed results (v0.10: a per-host Ed25519 key, so the stored records are evidence even
against a compromised server) and a webhook for regressions and silent hosts (v0.11).

**Also shipped:** scanning container images from a `docker save` or OCI archive (v0.12), a GitHub Action (v0.13),
the `essentials` profile (v0.14; kernel parameters in revision 2, v0.17), policy packs, your own checks and profiles
(v0.15), a Markdown output and a job summary in the Action (v0.16), `hostlint explain` and `hostlint pack facts` (v0.18),
fix hints in the results (v0.21), a firewall and automatic updates in `essentials` (revision 3), policy-pack and image results in the fleet server (ADR 0016), a container image of every release (ghcr.io, [docs/container.md](container.md)), a profile selector in the dashboard (v0.19) and the outbound agent for on-demand scans with an operator scope
(v0.20, [ADR 0014](adr/0014-the-outbound-agent.md)).

**Next:**
- Roles beyond viewer and operator, and OIDC inside hostlint: not now ([ADR 0015](adr/0015-dashboard-sign-in.md); an
  authenticating proxy works today).
- PostgreSQL as an option; waivers managed in the UI.

## Later

- CIS mapping overlays (control IDs only); packs in the agents, packs as a signed bundle or from a registry.
- More distros (SUSE); scanning an image straight from a registry, zstd layers, an OCI layout directory (#164), an Alpine package reader (#165).
- Notifications beyond the webhook.
