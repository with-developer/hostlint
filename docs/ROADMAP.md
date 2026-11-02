# Roadmap

High-level plan. Day-to-day work is tracked in GitHub milestones and issues; this file changes
only when direction changes (record why in an ADR).

## v0.1 — Standalone CLI

**Goal:** download one binary, run `hostlint scan`, get a trustworthy per-control report.
**Scope:** Ubuntu 22.04/24.04/26.04, Debian 12/13, RHEL-compatible 9/10 (Rocky Linux,
AlmaLinux), and CentOS/RHEL 7 (best-effort: past end-of-life, but still common among Korean
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
   aging — never hashes), sysctl.
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
12. **Config file** — `hostlint.yaml`: profile selection, disabled checks, waivers with reason
    and expiry.
13. **Container e2e matrix** — Docker-based end-to-end tests per supported distro (including
    `centos:7`) with hardened and default fixtures and golden results, in CI.
14. **Release pipeline** — GoReleaser (linux amd64/arm64), checksums, cosign keyless signing,
    SBOM, .deb/.rpm, install script. Tagging `v0.1.0` requires the owner's approval.
15. **Docs** — README (EN) with a demo GIF, Korean translations of user-facing docs
    (`*.ko.md`), generated rule reference, CONTRIBUTING (how to write a check), SECURITY.md,
    and a CI check that flags English user docs changed without their `.ko.md`.
16. **Landing page** — project site on GitHub Pages (no custom domain without the owner's
    approval).

## v0.2 — Fleet mode

- `hostlint server`: single binary, embedded web UI (React + Vite + shadcn/ui), SQLite by
  default, PostgreSQL optional.
- `hostlint agent`: dials out over a gRPC bidirectional stream with mutual TLS; enrollment flow.
- Scan history, drift between scans, waivers managed in the UI.

## Later

- CIS mapping overlays (control IDs only), custom policy packs.
- More distros (Amazon Linux, SUSE); container image / rootfs scanning.
- Remediation hints, scheduled scans, notifications.
