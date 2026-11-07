# Policy packs: your own checks and profiles

A policy pack is a directory with your own checks and profiles, in the format of hostlint's built-in
content. It lets a team check its own standard (an internal baseline, a customer's requirements, one more
thing to look at in `/etc`) without forking hostlint. [ADR 0012](adr/0012-policy-packs.md) has the decisions
behind it.

[한국어](packs.ko.md)

```sh
hostlint pack test ./acme-pack                 # load it, run the tests of its checks
hostlint pack show ./acme-pack                 # what it does, for the person who reviews it
hostlint scan --pack ./acme-pack -p x-acme-baseline
hostlint scan --pack ./acme-pack -p kisa-2026 -p x-acme-baseline   # both, in one scan
```

## What a pack can and cannot do

A pack adds **no capability**. Its checks are the same declarative YAML with the same CEL expressions
as the built-in ones, evaluated against the facts the compiled-in collectors produce. It cannot add a
collector, a fact, a command or a function, so it cannot run anything, and it cannot read the contents of
anything a built-in check cannot read: the sensitive-path denylist applies to it unchanged.

It is **trusted like `hostlint.yaml`, not sandboxed against a hostile author**. A pack chooses what is shown
as evidence (the names, owners and modes a file check lists, and any fact its expressions render), which
collectors run, and, through its profile, which checks count and at which severity. So read it with
`hostlint pack show` before you use a pack you did not write, and use packs of people you trust.

hostlint holds a pack to more than the built-in content, so that it cannot make a result look better than
it is:

- the area of every check starts with `x-` (`x-acme.motd-owned-by-root`) and the ID of every profile starts
  with `x-` (`x-acme-baseline`): a result's check reference tells a pack's check from a built-in one, and
  nothing collides with built-in content or with another pack;
- a profile may not take the title of another profile;
- a parameter a profile sets for a check is as strict as the check's default or stricter (to accept a weaker
  setting, write a check of your own); other kinds of parameters have to keep their default;
- a control is raised to the severity of the checks it maps, because `--fail-on` gates on the severity of
  the control (the scan says so);
- a file check lists at most 10 paths, with at most 2 wildcard elements each, none under `/proc`, `/sys` or `/dev`;
- every check needs a PASS test, a FAIL test and a test where its input is absent, unavailable or incomplete,
  as the built-in checks do (ADR 0006).

## Layout

```text
acme-pack/
  pack.yaml
  rules/x-acme/motd-owned-by-root.yaml     # one check, rules/<area>/<name>.yaml; the ID is x-acme.motd-owned-by-root
  profiles/x-acme-baseline.yaml            # one profile, profiles/<id>.yaml
```

`pack.yaml`:

```yaml
format: 1                  # the version of the pack format
name: acme                 # kebab case; results name the pack by it
version: 1.2.0             # letters, digits and . _ + -
description: Acme's baseline            # optional
requires_hostlint: v0.15.0              # optional: the oldest release the pack works with
```

Checks and profiles are written as described in [CONTRIBUTING](../CONTRIBUTING.md#how-a-check-is-built)
and in the [rule reference](rules.md); [`examples/policy-pack`](../examples/policy-pack) is a small working
pack. A profile can map built-in checks and your own:

```yaml
id: x-acme-baseline
revision: 1
title: Acme baseline
controls:
  - id: ACME-01
    title: Root does not log in over SSH
    severity: high
    checks: [ssh.permit-root-login, ssh.match-permit-root-login]
  - id: ACME-02
    title: Passwords are long and expire within 60 days
    severity: high
    checks: [accounts.password-min-length, accounts.password-max-age]
    params:
      accounts.password-max-age: {max_days: 60}
  - id: ACME-03
    title: The login banner belongs to root
    severity: low
    checks: [x-acme.motd-owned-by-root]
```

Bump `revision` when you change a profile.

## Using a pack

`hostlint scan --pack DIR` (repeatable; also `HOSTLINT_PACK`, a list of directories separated like `PATH`)
loads the pack next to the built-in content; `--profile` selects a profile of the pack, and can be repeated to
scan several profiles at once (the checks they share are evaluated once). A pack that is loaded and none of
whose profiles is selected is an error, not a scan that quietly ignores it. The pack is read from the machine
that runs hostlint, never through `--root` or `--image-tar`, and never found by itself in the current directory.

The result says which pack it came from: `scan.packs` has its name, version and digest (the SHA-256 over the
sorted paths and contents of the files that were read). `hostlint diff` and `hostlint report` warn when two
results used different packs, or the same profile revision with another content.
`hostlint.yaml` can refer to a pack's checks and controls (parameters, waivers). A waiver of a control of a
pack's profile names the digest of the profile (`digest:`, shown in the error that asks for it, in the result
and by `pack show`). The digest covers what the control maps and what the pack's own checks that it maps do, because a pack
author can change either without changing the revision.

`--verify-pack` runs the tests of the pack's checks before the scan and refuses to scan with a pack that
fails them. Tests catch mistakes, not malice (the author writes the logic and the tests), and they cost time
on every host, so they belong to the pack's own CI: run `hostlint pack test` there.

`--push` is refused for a scan with a pack: the fleet server cannot tell which pack a result came from yet.

## How a pack is read

The pack is read from a directory anyone with the right to write there could have changed, so it is read
carefully: through a root that cannot be left (no symbolic link is followed), every directory and file owned by root
or by you and not writable by group or others (`chmod -R go-w`), nothing but `pack.yaml`, `rules/<area>/<name>.yaml`
and `profiles/<id>.yaml` (any other file is an error, not something that is skipped), at most 4 MiB, 256 KiB per
file, 300 checks, 50 profiles and 200 entries per directory. Each file is opened once, and what is hashed
is what is parsed. Running `sudo hostlint scan --pack ./pack` over files of another user, a container as root over a
CI workspace of another user, and a Kubernetes ConfigMap (a farm of links) are refused for that reason: copy the pack
to a place you own.

## The format is not frozen

Before v1.0 the format of checks and the facts they read can change in a minor release; the release notes
say when a pack has to change. `requires_hostlint` keeps a pack from running on a hostlint that is too old.
