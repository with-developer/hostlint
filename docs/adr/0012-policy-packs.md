# 0012. Policy packs: your own checks and profiles

- Status: Accepted (the owner approved it on 2026-11-07, as proposed; see "Decisions")
- Date: 2026-11-07

## Context

Checks are data (ADR 0003, 0006): YAML files that compare facts with what is expected, mapped to controls
by profiles. The vision promises that "the same checks map onto KISA, CIS (control IDs only) or your own
policy", and ADR 0006 expects external rule packs. A team has its own standard (an internal baseline, a
customer's requirements, one more thing to look at in `/etc`), and today the only way to add it is to fork
hostlint and rebuild the binary.

This proposal was reviewed by an independent agent before it was written down. Its findings changed
the design below; the biggest one is that a pack is **not** as safe as the built-in content, and the ADR
has to say so.

## Proposal

- A **policy pack** is a directory (later perhaps one file) with a manifest `pack.yaml` (`format: 1`,
  `name`, `version`, `requires: hostlint >= X`), `rules/<area>/<name>.yaml` (checks) and
  `profiles/<id>.yaml` (profiles), in the format of the built-in content. `hostlint scan --pack DIR`
  (repeatable; also `HOSTLINT_PACK` and an input of the GitHub Action) loads it next to the built-in
  content. `--profile` becomes repeatable, so "KISA plus our checks" needs no copy of the KISA mapping.
  A pack that is loaded and whose profile is not selected is an error, not a silent no-op.
- **What a pack cannot do.** It adds no collector, fact, command or CEL function. It cannot run anything
  or read the contents of anything a built-in check cannot: the sensitive-path denylist and the
  observation-only rules apply unchanged.
- **What it can do, which the built-in content cannot be accused of.** It chooses what is shown as
  evidence (names, owners and modes that a `file` check lists for any glob, and any fact a `manual.show`
  or `violations.text` renders), which collectors run, and, through its profile, which checks count and
  at which severity. So a pack is **trusted like `hostlint.yaml` or a reviewed change, not sandboxed
  against a hostile author**. The tools of the reviewer are `hostlint pack show DIR` (the collectors,
  fact paths, globs and `show` expressions the pack uses; the severity and mapping of every control) and
  the pack digest.
- **Profiles cannot weaken what they map.** A pack profile's parameter for a built-in check must be as
  strict as the check's default or stricter (a weaker value is a load error: write your own check), and
  a control's severity is clamped up to the highest severity of the checks it maps (`--fail-on` gates on
  the control's severity). A pack profile may not reuse the ID or title of a built-in profile.
- **Provenance is visible in the result.** Pack check areas and pack profile IDs carry a reserved prefix
  that built-ins promise never to use (`x-acme.password-age`, profile `x-acme-baseline`), so a `ref`
  tells a pack check from a built-in one without a list, and a later built-in area cannot collide. IDs
  that collide across several `--pack` arguments are an error. The result carries the pack's name,
  version and digest (the digest covers the sorted paths and the bytes that were parsed), which needs an
  additive change of `schema/result-v1.schema.json`. `hostlint diff` and `report` warn when the profile
  and revision are the same but the digest is not, and when two results used different packs. Waivers of
  a pack control are bound to the profile digest.
- **Tests.** Loading a pack validates it as the built-in content is validated (type-checked expressions,
  a PASS, a FAIL and an absent-input case per check), which is cheap and stays on every scan. The
  behavioural tests run in `hostlint pack test DIR` (for the pack's own CI) and behind `scan
  --verify-pack`, not on every scan: they would add latency and a new failure mode to every host after
  an upgrade, and they catch mistakes, not malice (the author writes both the logic and the tests; a
  fact name with a typo passes a test that has the same typo). A loader lint checks the literal fact and
  setting keys against the keys the collectors really emit.
- **Loading.** The pack is read from the machine that runs hostlint, never through `--root` or
  `--image-tar`, and never discovered from the current directory. The loader opens the root with
  `os.OpenRoot` (no symbolic link, nothing outside), checks that the pack root and every directory in it
  are owned by root or the user and not writable by group or others, reads every file once, hashes those
  bytes, parses those bytes and gives `Load` an in-memory file system: no check-then-use gap. Only
  `rules/**.yaml`, `profiles/*.yaml` and `pack.yaml` are allowed; any other file there is an error.
  Bounded: about 4 MiB in all, a small number of files and of entries per directory, and a cap on the
  checks per pack and on the file globs of a `file` check (few wildcard elements, none under `/proc`,
  `/sys` or `/dev`). The ownership rule will refuse common setups (`sudo` over files of another user,
  a root container over a CI workspace, Kubernetes ConfigMap symlinks): the errors name the fix.
- `scan --push --pack` is refused until the result carries the pack's identity; the server and the
  agents ignore packs.

## Consequences

- A team keeps its policy in its own repository, tests it with `hostlint pack test`, and uses it in CI
  with the GitHub Action or the CLI, without rebuilding hostlint.
- A pack can only look at what the collectors expose; a new kind of observation still means a collector
  in hostlint (reviewed as code, ADR 0004).
- The rule format becomes a contract authors depend on while it is not frozen: before v1.0 it can
  change in a minor release, and the release notes say when a pack has to change (`requires`).
- The JSON schema of the result gets a new optional member, and `diff` and `report` get new warnings.

## Decisions

The owner approved the proposal as written on 2026-11-07 (issue #162):

1. **Packs are wanted before v1.0**, with the safeguards above: trusted like `hostlint.yaml`, never
   weaker than a built-in check, visible in the result, never loaded implicitly.
2. **The result schema gets an additive member** for the pack's name, version and digest.
3. **The reserved `x-` prefix** is the provenance mechanism. The pack identity (digest, schema member),
   the `diff` and `report` warnings and the refusal of `--push` ship together with `scan --pack`; the
   work is staged in separate pull requests (loader, `pack test` and `pack show`; then the result
   identity with `scan --pack`, repeatable `--profile` and `--verify-pack`) and released once.
4. **Distribution and signing of packs** (a single-file bundle with its digest as the identity, a
   registry) are left for later.
