# 0015. Signing in to the dashboard: roles and OIDC

- Status: Accepted (the owner approved the recommendations on 2026-11-07, issue #189)
- Date: 2026-11-07

## Context

The dashboard signs a person in with an `api` token that is exchanged once for a session cookie (ADR 0010). The
ROADMAP lists "roles and OIDC for the dashboard". Two things are mixed in that line:

- **Roles** only matter when someone can change something in the dashboard. Today it only reads. Everything that
  changes the server (tokens, host deletion, pruning, resetting a key) is a command line action, audited, done on the
  machine that holds the database.
- **OIDC** (a company's sign-in: Google, Entra ID, Okta, Keycloak) matters for who may *read* the fleet's results, which
  can name every weak host of a company. Today that is whoever has an `api` token.

## Decisions (recommendation first)

1. **Roles: not now.** Recommended: add roles together with the first feature that writes (the "scan now" button of
   ADR 0014, editing waivers in the UI), not before: a role that decides nothing is a field to keep consistent.
   When they come: `viewer` (reads), `operator` (scan now), `admin` (tokens, hosts, waivers), carried by the
   credential, audited.
2. **OIDC: put an authenticating proxy in front, for now.** Recommended: document the pattern that works today with
   no code: the server on a loopback address or a unix socket behind a reverse proxy that does the sign-in (oauth2-proxy,
   an identity-aware proxy, nginx with auth) and passes the request on with an `api` token of its own. It needs
   nothing from hostlint and keeps a sign-in implementation (the most attacked part of any web application) out of the
   fleet server.
3. **If native OIDC is wanted later**, the recommendation is `github.com/coreos/go-oidc/v3` with `golang.org/x/oauth2`
   (authorization code with PKCE, the ID token verified against the provider's keys, a role taken from a claim)
   rather than writing token verification here. That is a new dependency, so it needs the owner's decision when it is
   needed; it is not decided now.

## Consequences

- Nothing to build now. docs/fleet.md gets a section on the proxy pattern (with the settings that make it safe:
  `--behind-proxy`, a listen address that is not reachable except by the proxy, a token that never leaves the proxy).
- The decision on roles and native OIDC is made with a real use in front of us.

## What the owner decided

Approve, change or decline the three points. Approving the recommendations means: add the proxy section to the docs, and
revisit roles and OIDC when a writing feature or a user asks.
