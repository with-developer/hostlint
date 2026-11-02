# 0003. Separate checks from control mappings

- Status: Accepted; the first overlay is amended by [ADR 0007](0007-kisa-2026-edition.md)
- Date: 2026-11-02

## Context

Standards bundle settings differently. KISA U-01 covers both telnet and SSH root login; U-02
covers several password-complexity settings. One check passing must never read as a control
passing. Standards are also revised over time, and their texts carry different licenses:
CIS Benchmarks are published under CC BY-NC-SA 4.0.

## Decision

- **Checks** are standard-agnostic observations with stable IDs (e.g. `ssh.root-login-disabled`).
- **Control mappings** are versioned overlays per standard (e.g. `kisa-2021`) that map each
  control to one or more checks (many-to-many) with explicit aggregation. A control passes only
  if all of its mapped checks pass; controls that cannot be automated are `MANUAL`.
- All rule titles and descriptions are written by us. We reference control IDs; we do not
  reproduce benchmark text.
- The first overlay is KISA CII Unix (U-01–U-72). CIS overlays come later, with IDs only.

## Review

The counter-review (Grok, 2026-11-02) proposed the split and the versioning; accepted. It also
suggested that mirroring a benchmark's control structure might carry license risk even without
copying text. Not verified — revisit before the first CIS overlay.

## Consequences

- Adding a standard means writing a mapping, not duplicating checks.
- Results answer "which controls of profile X pass on host Y" — what auditors actually need.
