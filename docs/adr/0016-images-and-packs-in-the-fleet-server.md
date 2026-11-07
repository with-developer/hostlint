# 0016. Images and policy-pack results in the fleet server

- Status: Proposed (waiting for the owner's decision, issue #208)
- Date: 2026-11-08

## Context

The fleet server (ADR 0010) keeps the results of **hosts**. Two kinds of result cannot be pushed today, and both
refusals are in the client (`scan --push`), not in the server:

- **A container image** (`scan --image-tar`, ADR 0011) has no machine ID: its name is the image reference, and the
  rule "a known name never gets a second host ID" is about machines. CI is where images are scanned, and "which of
  our images got worse, and which tag fixed it" is what a team would look at in a dashboard.
- **A result of a policy pack** (ADR 0012) carries `scan.packs[]` (name, digest, checks and profiles) since v0.15.
  `--push` is refused with a pack because the dashboard did not know what to do with a profile it has no content
  for. The server does not need the content to store a result: it keeps the document and the controls and titles
  the result itself carries (`scan_controls`), and the per-profile views (ADR 0014 era, #177) work from the
  profiles found in the results.

What is needed is a decision about identity and display, not a new transport.

## Options and recommendation

1. **Packs first.** Lift the refusal of `--push` with `--pack`. The result is stored as it is. The host page shows
   the pack's name and digest next to the profile, the profile selector lists the profiles found in the received
   results (titles from the result when the server has no built-in profile of that ID), and the overview of a pack's
   profile counts the hosts that scanned it. A pack is chosen by the host, as a profile and its waivers already are:
   the result says which pack and which digest produced it (it is part of what a signed result covers), and the
   dashboard shows it. Nothing is evaluated or trusted on the server. Recommended.
2. **Images as a second kind of asset.** A `kind` column on `hosts` (`host` default, `image`), additive
   migration. An image's name is the reference without the tag (`ghcr.io/acme/app`) and it has no host ID; each
   scan records the image digest and the tag in `scan.target` (`target.image`: reference, digest; an additive
   schema field; `target.kind` stays `root` for readers that do not know it). So the history of an image is the
   sequence of its digests and tags, and the dashboard gets an **Images** list next to **Hosts** (an image is never
   "stale": nothing reports for it on a schedule, so it is left out of the stale counts and of the host statistics
   of the overview). `scan --image-tar --push` is allowed with `--name` for the asset name when the archive does not
   carry a clean reference; a token is bound to an exact name or to a prefix (`--host 'ghcr.io/acme/*'` for an
   organization's CI), checked on every result. Recommended, as a second step after 1.
3. **Images as hosts** (no `kind`): an image would be a host named by its reference with no ID, one row per tag.
   Smaller, but every host statistic (stale, "hosts failing", the number of hosts) would count images, and an old
   tag would look like a host that stopped reporting. Not chosen.
4. **Not now.** Both stay refused; CI uses SARIF in code scanning and the job summary (docs/ci.md). A fine answer if
   the fleet server is not where image results should live.

## Consequences

- With 1 and 2, `docs/fleet.md` gains a section on pushing from CI (`scan --image-tar app.tar --push ...` with a token
  bound to the image prefix), and the Action gets an optional `push` input (a token from a secret: the owner's
  approval is needed before documenting a secret-bearing step as the default, so it stays opt-in).
- The audit chain and signatures are unchanged; an image result is signed like any other when the token is bound to
  a key.
- Schema: `scan.target.image` is optional and additive (version stays 1). Migration 0007 adds `hosts.kind` with a
  default, so existing data is untouched and the change can be reverted by ignoring the column.
- Not decided here: image scans on a schedule by the server (the server never scans: ADR 0001), registry scanning,
  deleting old tags (the existing prune keeps the latest scan of every asset).

## What the owner decides

Approve 1 and 2 as recommended (in two steps), only 1, or neither. The agent (ADR 0014) is unaffected.
