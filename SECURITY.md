# Security policy

hostlint runs as root on servers that matter, so we take reports seriously.

## Reporting a vulnerability

Please **do not open a public issue**. Report it privately through
[GitHub's private vulnerability reporting](https://github.com/with-developer/hostlint/security/advisories/new)
with:

- what an attacker can do, and under which conditions (local user, crafted file on the scanned
  host, crafted rule or profile, …);
- the hostlint version or commit, and the steps or files to reproduce it.

We fix confirmed issues before disclosing them and credit reporters who want to be credited.

## What counts

hostlint promises that a scan never changes the scanned host, never runs a command a rule asks
for, never puts secrets (password hashes, private keys, tokens) in its output, and never reports
`PASS` for something it could not decide. A way to break any of these is a vulnerability, for
example:

- a file on the scanned host that makes hostlint write, delete or change something;
- input that makes hostlint execute a program or follow a path outside the scanned root;
- a password hash, key or credential that ends up in a result, log or error;
- a configuration that hostlint reports as `PASS` while it is not met (a false PASS).

## Supported versions

Until v1.0, only the latest release gets fixes.
