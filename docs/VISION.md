# Vision

> **vmsctl is eslint for Linux servers** — a single Go binary that checks a host's
> security configuration against hardening baselines, from one server to a fleet.

## Problem

Checking whether a Linux server is hardened is still done in one of two ways:

- **Shell scripts that print text for humans.** Easy to start, hard to trust: results are
  parsed with regexes, every distro gets its own copy of the script, and extending them
  means editing thousands of lines of shell.
- **Heavyweight compliance platforms.** Powerful, but they take days to deploy, and their
  rule formats are hard to read or contribute to.

## What vmsctl is

- **One binary, zero setup.** Download, run `vmsctl scan`, get an answer in seconds.
- **Rules as data.** Checks are declarative YAML that anyone can read, review and contribute.
- **Standards as overlays.** The same checks map onto KISA, CIS (control IDs only) or your
  own policy. Results are reported per control, with the evidence behind each verdict.
- **Structured results.** JSON first; SARIF and JUnit for CI; a terminal view for humans;
  a static HTML report that merges many hosts.
- **Fleet when you need it.** The same engine powers an agent/server mode with a built-in web UI.

## Who it's for

1. **DevOps/SRE engineers** checking golden images in CI and live hosts in production.
2. **Security and compliance teams** reporting per-control status across many servers —
   for example, Korea's KISA Critical Information Infrastructure (CII) assessment.
3. **Self-hosters** who want a quick sanity check of their VPS.

## Principles

These are non-negotiable. Changing one requires the owner's approval and an ADR.

1. **Observation only.** A scan never changes the host. Rules cannot execute commands;
   commands needed to gather facts (e.g. `sshd -T`) live in compiled-in collectors and are
   reviewed as code.
2. **Secrets never leave the host.** Collectors never emit password hashes, private keys or
   tokens. Sensitive paths are denied to generic file reads, and results carry evidence
   summaries rather than raw file contents.
3. **Server compromise must not become fleet compromise.** In fleet mode the agent dials out
   over mutual TLS and performs only the observations its own collectors and denylist allow,
   whatever the server asks for.
4. **No false PASS.** A wrong PASS is worse than a missing check. Controls that cannot be
   decided automatically are reported as `MANUAL`, never guessed.
5. **Clean-room content.** Rule text is our own. Benchmark text under restrictive licenses
   (e.g. CIS Benchmarks, CC BY-NC-SA 4.0) is never copied; we reference control IDs only.
6. **Boring to install and run.** Static binary, no runtime dependencies, signed releases, SBOM.

## Non-goals

- Package/CVE vulnerability scanning — use Trivy, Grype or Vuls.
- Automatic remediation — vmsctl may print fix hints; changing hosts is a job for
  configuration management tools.
- Log analysis, SIEM, intrusion detection — use Wazuh or Falco.
- Kubernetes cluster benchmarks — use kube-bench.
- Windows hosts (for now).

## Lineage

vmsctl is a ground-up rewrite of VMS (2023–2024), which ran server vulnerability checks from
a central Flask/MongoDB server. It keeps the goal — see many servers' hardening status in one
place — and changes the architecture: outbound mTLS agents instead of listening ones,
declarative checks instead of per-distro shell scripts, structured results instead of parsed text.
