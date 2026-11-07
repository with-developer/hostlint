# 0014. The outbound agent

- Status: Accepted (the owner approved the recommendations on 2026-11-07, issue #188)
- Date: 2026-11-07

## Context

ADR 0001 chose a pull-based fleet: the agent dials out, the server never connects to a host. ADR 0010 shipped
phase 1 without it: hosts push results (`hostlint scan --push`, with signed results, tokens bound to a host and a
key, a webhook for regressions and silent hosts), and left "the agent over gRPC with mutual TLS" for its own ADR.

What an agent adds over a timer that runs `hostlint scan --push` is small, and it is the dangerous part:

- **Scheduling** needs no agent: a systemd timer or a cron job does it, on the host's own terms.
- **On-demand scans** ("scan this host now", from the dashboard or after a change) need the server to be able to
  ask a host to do something. That is the one thing the vision's principle 3 is about: whatever the server asks, the
  agent performs only the observations its own collectors and denylist allow. A compromised server must not
  become a compromised fleet.
- **Enrollment and rotation of the credential** (a token today, bound to a host and optionally to a key) are done
  by hand.

## Decisions (recommendation first)

1. **Do something now, and keep it small.** Recommended: ship the timer documentation first (a systemd unit and timer
   that run `hostlint scan --push`; no code) and build `hostlint agent` only for on-demand scans. Not chosen: a full
   agent with its own scheduling, policy distribution and remote configuration (the dangerous surface, with no
   gain over a timer).
2. **Transport.** Recommended: HTTPS long polling with the standard library: the agent asks `POST /api/v1/agent/poll`
   with its token, the server holds the request for up to 60 seconds and answers with a job or `204`. No new
   dependency, works through proxies and load balancers, and the agent still opens no port. Not chosen: gRPC
   (ADR 0001's idea): a bidirectional stream gives nothing a long poll does not for one job type, and it adds
   `grpc-go` and protobuf (a larger binary, HTTP/2-only proxies, a code generator).
3. **What the server may ask.** Recommended: exactly one job, "scan now", for a profile that is in an allowlist the
   *agent's own* configuration holds (`--allow-profile`), at most once a minute, with no arguments from the server
   except the profile. No waivers, parameters, commands, paths or configuration travel from the server: `hostlint.yaml`
   stays a file of the host. The result goes back the way it goes today (`POST /api/v1/results`, signed when the
   host has a key). A server that is compromised can make hosts scan more often, up to the limit; nothing else.
4. **Identity.** Recommended: the agent keeps using its ingest token (bound to its host name, pinned to its host ID)
   and the server's pinned public key (`--pin`), and the result stays signed with the host's key. Mutual TLS with a
   certificate issued at enrollment and rotated is a later step with its own ADR: it solves the lifetime of a long-lived
   token, not the question of what the server may ask.
5. **Dashboard.** A "scan now" button for an `api` token holder, audited like every other action; shown only for hosts
   that have an agent that polled in the last two minutes.

## Consequences

- With the recommendations, the agent is about 300 lines and one new endpoint, and the new attack surface is a job that
  can only say "scan with a profile you already allow".
- A host behind a firewall that allows outbound HTTPS only works, as for `--push`.
- Not decided here: scheduling inside the agent, policy distribution, remote configuration, mutual TLS enrollment.

## Implementation notes

Built as decided, with these particulars:

- A poll is held for 25 seconds, not 60 (the server's write timeout and proxies that cut a request after a minute);
  the agent asks again at once, so a healthy agent makes about three requests a minute, and a per-token limit of 12 a
  minute stops a runaway client.
- The button needs a new **operator** scope (ADR 0015's minimal "roles": `viewer` is `api`, `operator` is `api` plus
  asking for scans), not an `api` token: reading the fleet and making hosts scan are different powers. An operator
  token reads everywhere an `api` token does. Adding the scope rebuilt the `credentials` table (a `CHECK` cannot be
  altered), keeping its rows and the dashboard sessions.
- A browser session may ask for a scan only with a JSON body and an `Origin` that is the server's own site; sessions
  are still never accepted for any other change.
- A job claimed but never answered, or a request nobody took, expires after ten minutes; one request per host per
  minute, and one open at a time.
- The agent has no `--pack`: ADR 0012 keeps results of policy packs out of a fleet server for now.

## What the owner decided

Approve, change or decline the five points above. Declining 1 (no agent for now) leaves the documentation of timers as
the answer to scheduling; nothing else in the roadmap waits for it.
