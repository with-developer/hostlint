# How vmsctl compares

vmsctl is one tool among several that check a Linux server's configuration. This page says what it does differently,
and when another tool is the better choice. The other tools are described from their own documentation (linked at
the end); they change, so check them before you decide.

[한국어](comparison.ko.md)

## What vmsctl is, and is not

vmsctl reads a host's **configuration** (accounts, SSH, PAM, file permissions, services, kernel parameters, packages)
and reports one result per control, with the evidence behind it. It is **not**:

- a **vulnerability scanner** in the CVE sense. Tools such as Trivy or Grype look for known vulnerabilities in the
  packages of a host or an image; vmsctl looks at how the system is set up. The two answer different questions and
  are used together;
- a **remediation tool**. It never changes the host. A failed check says how to fix it; the fix is yours (or your
  configuration management's);
- a **CIS Benchmark scanner**. Its profiles are the KISA technical vulnerability guide (Unix, 2026 edition) and a short
  neutral `essentials` baseline, and you can write your own as a [policy pack](packs.md). The text of the CIS
  Benchmarks is not copied (its licence does not allow it); mappings by control ID are on the [roadmap](ROADMAP.md).

## Side by side

| | vmsctl | Lynis | OpenSCAP | Wazuh (SCA) |
|---|---|---|---|---|
| Form | One static Go binary; an optional server and dashboard, both Apache-2.0 | A shell-script tool for Unix-like systems (GPL); a paid SaaS tier adds a dashboard and more | `oscap` and the SCAP Security Guide content; reports as HTML | A module of the Wazuh agent; results in the Wazuh dashboard |
| What defines a check | YAML data and CEL expressions; rules cannot run commands | Tests built into the tool, plus plugins | SCAP content (XCCDF profiles, OVAL checks) | YAML policies run by the agent, CIS Benchmark-based ones included |
| Result | PASS, FAIL, ERROR, MANUAL, WAIVED, N/A, each with the value, the file and the line; what cannot be decided is ERROR or MANUAL, never a guessed PASS | A hardening index and suggestions | Pass or fail per rule of a profile | Passed, failed and not-applicable counts and a score per endpoint |
| Fixes | A "how to fix" text; never applies anything | Suggestions | Can apply fixes (`--remediate`) or generate a script | Recommendations in the policy |
| Container images | From a `docker save` or OCI archive, no daemon, nothing run | | | |
| Many hosts | Hosts push to a server that keeps the history, signed results, trends and a matrix; the server never connects to a host | Via the paid tier | Remote scans with `oscap-ssh`; keeping a fleet is for other tools | Wazuh manager and dashboard |
| Your own checks | [Policy packs](packs.md): YAML, tested, no new capabilities | Plugins | Writing SCAP content | Custom YAML policies |

Empty cells mean the page above does not say; they are not a claim that the feature is missing.

## When another tool is the better choice

- You need **remediation** applied for you, or **CIS Benchmark** content, or **SCAP** results to hand to an auditor
  who asks for them: OpenSCAP.
- You already run **Wazuh** for detection and want configuration assessment in the same agent and dashboard: its SCA module.
- You want a broad, long-established **audit of a Unix-like system** with hardening suggestions, on platforms other
  than Linux: Lynis.
- You need **CVE** matching: a vulnerability scanner, next to vmsctl.

vmsctl fits when you want results you can **trust and explain** (the evidence, no guessed pass), the KISA guide as a
built-in profile, container images checked in CI, and a fleet view that does not need an agent with a channel into your
hosts.

## Sources

- Lynis: [cisofy.com/lynis](https://cisofy.com/lynis/), [github.com/CISOfy/lynis](https://github.com/CISOfy/lynis/)
- OpenSCAP: [Red Hat, scanning the system for configuration compliance](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/security_hardening/scanning-the-system-for-configuration-compliance)
- Wazuh: [security configuration assessment](https://documentation.wazuh.com/4.14/compliance/nist/configuration-assessment.html)
