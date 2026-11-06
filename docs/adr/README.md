# Architecture Decision Records

One file per decision: `NNNN-short-title.md` with Status, Date, Context, Decision and
Consequences. Don't edit an accepted ADR to change a decision — add a new ADR that supersedes it.

| ADR | Decision |
|---|---|
| [0001](0001-go-single-binary-outbound-agent.md) | Go, single binaries, outbound agents |
| [0002](0002-cli-first.md) | Ship a standalone CLI first; fleet mode reuses it |
| [0003](0003-checks-and-control-mappings.md) | Separate checks from control mappings |
| [0004](0004-observation-only.md) | Observation-only scanning |
| [0005](0005-license-apache-2.md) | License: Apache-2.0 |
| [0006](0006-rule-format-evaluation-results.md) | Rule format (CEL), evaluation, statuses and result schema v1 |
| [0007](0007-kisa-2026-edition.md) | The KISA profile targets the 2026 edition (U-01–U-67) |
| [0008](0008-package-service-socket-facts.md) | Package, service and socket facts: files first, live state gated by `target.live` |
| [0009](0009-bounded-filesystem-walk.md) | Bounded filesystem walks: local filesystems only, partial lists never pass |
| [0010](0010-fleet-server-and-dashboard.md) | Fleet server and dashboard: hosts push results first, the outbound agent comes later (accepted) |
