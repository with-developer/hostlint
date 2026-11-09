# Security policy

vmsctl runs as root on servers that matter, so we take reports seriously.

## Reporting a vulnerability

Please **do not open a public issue**. Report it privately through
[GitHub's private vulnerability reporting](https://github.com/with-developer/vmsctl/security/advisories/new)
with:

- what an attacker can do, and under which conditions (local user, crafted file on the scanned
  host, crafted image archive, crafted rule or profile, a crafted result sent to the fleet server, …);
- the vmsctl version or commit, and the steps or files to reproduce it.

We fix confirmed issues before disclosing them and credit reporters who want to be credited.

## What counts

vmsctl promises that a scan never changes the scanned host, never runs a command a rule asks
for, never puts secrets (password hashes, private keys, tokens) in its output, and never reports
`PASS` for something it could not decide. A way to break any of these is a vulnerability, for
example:

- a file on the scanned host that makes vmsctl write, delete or change something;
- input that makes vmsctl execute a program or follow a path outside the scanned root, including a
  crafted container image archive (`--image-tar`), which is untrusted input: a name, a link or a layer
  that reaches the scanner's own files, a hard link that gets a denylisted file read, or a hostile
  archive that makes a check pass that should not;
- a password hash, key or credential that ends up in a result, log or error;
- a configuration that vmsctl reports as `PASS` while it is not met (a false PASS).

## Supported versions

Until v1.0, only the latest release gets fixes.
