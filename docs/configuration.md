# Configuration

hostlint runs without configuration. A `hostlint.yaml` lets you pick the profile, make checks
stricter, accept findings you have decided to live with (waivers), and record a human verdict for
checks only a person can judge (attestations).

[한국어](configuration.ko.md)

```yaml
# The profile to scan with when --profile is not given.
profile: kisa-2026

# Stricter thresholds than the profile's: check ID → parameter → value.
params:
  accounts.password-max-age: {max_days: 60}
  accounts.lockout-threshold: {max_failures: 5}

waivers:
  # Accept the result of one check, on some hosts.
  - check: files.shadow-perms
    reason: Debian's unix_chkpwd reads /etc/shadow through group shadow
    expires: 2027-06-30
    hosts: ["web-*"]
  # Accept a control of the profile.
  - control: U-18
    revision: 2
    reason: Accepted by the security team (SEC-142)
    expires: 2027-01-31

# A recorded human verdict for a MANUAL check.
attestations:
  - check: accounts.review-login-accounts
    status: PASS
    digest: sha256:527ee5b7d83f8…           # checks[].digest of a JSON result
    evidence_digest: sha256:c415c5c4f23ba…  # checks[].evidenceDigest of the same result
    by: alice
    at: 2026-11-05
    expires: 2027-02-01
    reason: Reviewed the login accounts with the team
```

## Where hostlint looks

1. the file given with `--config` (it must exist);
2. `hostlint.yaml` in the working directory;
3. `/etc/hostlint/hostlint.yaml`.

The first one found is used; none is fine. The file belongs to the machine running hostlint: with
`--root`, it is not read from the mounted filesystem.

Waivers can hide findings, so hostlint refuses a file that someone else could have planted or
changed: it must be a regular file owned by root or by the user running hostlint, and not
writable by group or others. Running `sudo hostlint scan` in a directory with a `hostlint.yaml`
that you own fails for this reason; make root its owner (`sudo chown root: hostlint.yaml`).

The file is read strictly. Unknown keys, checks, controls and parameters are errors, so a typo
never drops a waiver silently. `--profile` on the command line wins over `profile:`.

## Parameters

Some checks have thresholds, declared under `params` in the check's file in [rules/](../rules/)
(for example `max_days` in `rules/accounts/password-max-age.yaml`). The profile sets the
values it requires; `params:` in `hostlint.yaml` can override integer parameters, but only in
the stricter direction (`stricter: lower` or `higher` in the check). A weaker value is an error
that points you to waivers, so a `PASS` always means at least the profile's thresholds.

Results evaluated with overridden parameters are marked `customized` in the JSON result.

## Waivers

A waiver accepts a result for a reason, until it expires. The check still runs: the result is
reported as `WAIVED` with the reason, and keeps its original status and evidence.

| Key | Meaning |
|---|---|
| `check` or `control` | Exactly one: a check ID, or a control ID of the profile being scanned |
| `reason` | Required. Why the result is accepted |
| `expires` | Required. The last day the waiver applies, `YYYY-MM-DD` (UTC) |
| `revision` | Control waivers only, required: the profile revision the waiver was written for |
| `hosts` | Hostname globs such as `web-*`; the waiver applies to every host when omitted |
| `errors` | `true` to also accept `ERROR`: a deliberate decision that the check cannot run there |

- A waiver changes `FAIL` and `MANUAL` results, and `ERROR` only with `errors: true`. `PASS`
  and `NOT_APPLICABLE` stay as they are.
- A control waiver applies to the control's combined result. It does not apply while any of the
  control's checks is `ERROR`, and it stops applying when the profile's revision changes, so
  checks added to the control later are not accepted without a look. The validation error for
  a missing `revision` tells you the current one.
- Expired and stale waivers stop applying. The scan lists them: below the summary in the table,
  and under `waivers` in the JSON result.

## Attestations

Some checks only list what a person has to judge (the accounts that can log in, the time
servers in use). They are `MANUAL`. After you have looked, an attestation records your verdict,
`PASS` or `FAIL`, and the control follows it. The result keeps `originalStatus: MANUAL`, says
`statusSource: attested`, and carries who attested, when, and why.

An attestation is not a blanket exception. It is bound to what you looked at:

- `digest` is the digest of the check's logic. It changes when a hostlint release changes the check.
- `evidence_digest` is the digest of the full value the check shows (not the truncated evidence in
  the report). It changes when the accounts, servers or files it lists change.

Read both from a scan's JSON result (`hostlint scan --format json`): `checks[].digest` and
`checks[].evidenceDigest` of the check. A check that shows nothing has no `evidenceDigest`; leave
`evidence_digest` out, and the attestation applies until it expires.

| Key | Meaning |
|---|---|
| `check` | Required. A check ID; only a check that is `MANUAL` can be attested |
| `status` | Required. `PASS` or `FAIL` |
| `digest` | Required. The check's `digest` |
| `evidence_digest` | Required for a check that shows a value; leave it out for a check that shows nothing |
| `by` | Required. Who looked |
| `at` | Required. The day of the verdict, `YYYY-MM-DD` |
| `expires` | Required. The last day it applies, `YYYY-MM-DD` (UTC) |
| `reason` | Required. What you checked and why the verdict holds |
| `hosts` | Hostname globs such as `web-*`; every host when omitted |

- An attestation applies to `MANUAL` results only. If the check is `ERROR`, `FAIL` or `PASS`, it
  is not applied.
- It stops applying when it expires, when the check changes (including when it starts or stops
  showing a value), when the observed value changes, or when the value could not be fully observed
  on this host. An attestation dated in the future does not apply yet. The scan lists such attestations (below
  the summary in the table, and under `attestations` in the JSON result), so a stale one is never
  silently ignored.
- Attestations apply before waivers: an attested `FAIL` can still be waived.
- Like waivers, they hide findings, so the file must be owned by root or the invoking user and
  not writable by others.
