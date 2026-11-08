# Fleet server (early)

> Phase 1 of [ADR 0010](adr/0010-fleet-server-and-dashboard.md): the server receives and stores
> results and answers read requests. The dashboard comes next. Treat the interface as unstable.

Hosts scan themselves and **push** the result to a server. The server never connects to a host:
it cannot make one scan, run anything or read anything there.

## Dashboard

`hostlint server run` serves a web dashboard at its address when the binary was built with it: the
release binaries are, and a source build uses `make build-web` (Node 22). A binary from `go install`
has the API only and says so at `/`. Sign in with a read token (`hostlint server token create --scope
api`): the dashboard shows the fleet overview (pass rate, the pass rate over time for 7, 30 or 90 days, hosts with a failing control, hosts that
stopped reporting, the controls that fail most, recent regressions), the host list (search, filters,
sorting, CSV export, and for each host its operating system, labels, a trend line of its latest scans and whether
its agent is connected), a list of controls (and for each one what it checks, why it matters, how to fix it and the hosts that fail it), a matrix of every control on every host, and for each host its controls with the evidence of every check, its history and a
comparison of any scan with the one before. It is available in English and Korean and follows the
system's light or dark theme. Everything a host sent is shown as text.

## Try it without any host

```sh
hostlint server demo
```

starts a server on `127.0.0.1:8443` with a made-up fleet (twelve hosts, two weeks of scans, built from
the real controls) and prints a read token to sign in with. The data lives in memory and is gone when
the command ends. It needs a binary with the dashboard (a release binary or `make build-web`).

## Quick start

On the server machine:

```sh
# One token per host. It is shown once; only its hash is kept.
hostlint server token create --db /var/lib/hostlint/server.db --name web-01 --host web-01

hostlint server run --db /var/lib/hostlint/server.db --listen :8443
# listening on https://[::]:8443
# certificate pin: sha256/JSofaoL4gyTKBhYAk1QjTRDCC93WqgtDa3AKhMzYk2U=
```

Without `--tls-cert` and `--tls-key` the server makes a self-signed certificate next to the
database and prints the pin of its public key. Plain HTTP is allowed only on a loopback address, or
with `--plain-http --behind-proxy` when a TLS proxy is in front.

On each host, scan and send in one command:

```sh
sudo HOSTLINT_TOKEN=hlt_ing_... hostlint scan \
  --push https://hostlint.example.org:8443 --pin sha256/JSofaoL4gyTKBhYAk1QjTRDCC93WqgtDa3AKhMzYk2U=
```

The scan runs first and its report is printed as usual (`--format`, `--output` and `--fail-on` work as
always); then the result is sent. A result that cannot be sent is an error (exit status 2), and a token
that is missing is found out before the scan starts. To send a result you saved earlier:

```sh
HOSTLINT_TOKEN=hlt_ing_... hostlint push result.json \
  --server https://hostlint.example.org:8443 --pin sha256/JSofaoL4gyTKBhYAk1QjTRDCC93WqgtDa3AKhMzYk2U=
```

The token comes from `HOSTLINT_TOKEN` or `--token-file`, never from the command line. With a
certificate from a public CA, leave `--pin` out. Run both steps from cron or a systemd timer.
Sending a result the server already has is not an error.

## Scheduled scans

The server never starts a scan; a host scans itself on a schedule and pushes the result. A systemd timer does it
(`/etc/systemd/system/hostlint-scan.service` and `.timer`):

```ini
# hostlint-scan.service
[Unit]
Description=hostlint scan, sent to the fleet server
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/hostlint scan --fail-on none --format json --output /dev/null \
  --push https://hostlint.example.org:8443 --pin sha256/JSofaoL4gyTKBhYAk1QjTRDCC93WqgtDa3AKhMzYk2U= \
  --token-file /etc/hostlint/token --sign-key /etc/hostlint/signing-key
NoNewPrivileges=yes
PrivateTmp=yes
```

```ini
# hostlint-scan.timer
[Unit]
Description=Daily hostlint scan

[Timer]
OnCalendar=daily
RandomizedDelaySec=2h
Persistent=true

[Install]
WantedBy=timers.target
```

```sh
sudo install -m 600 /dev/null /etc/hostlint/token      # then put the token in it
sudo hostlint key generate /etc/hostlint/signing-key   # prints the public key: bind the token to it with `server token create --key`
sudo systemctl enable --now hostlint-scan.timer
```

`RandomizedDelaySec` spreads a fleet over two hours (the server limits how fast one token may send), `Persistent`
runs a scan that was missed while the host was off. `--fail-on none` keeps a failing control from marking the unit
failed: a unit that fails means the scan or the sending did not work, and a failure state worth an alert.
`journalctl -u hostlint-scan` has the output. With cron, the same command in `/etc/cron.d/hostlint` (`17 3 * * * root ...`).
The server's `--stale-after` webhook tells you about a host that stopped reporting.

## On-demand scans: the agent

A timer scans on a schedule. To scan a host *now* from the dashboard, run `hostlint agent` on it as a service. The
agent only dials out (the server still never connects to a host): it keeps one HTTPS request open, a long poll, and
the server answers it when someone clicks **Scan now**.

```sh
sudo hostlint server token create --name web-01 --host web-01 --key <public key>   # the host's ingest token, as for --push (--key: the public key `key generate` printed)
sudo hostlint agent --server https://hostlint.example.org:8443 --pin sha256/JSofaoL4gyTKBhYAk1QjTRDCC93WqgtDa3AKhMzYk2U= \
  --token-file /etc/hostlint/token --sign-key /etc/hostlint/signing-key --allow-profile kisa-2026
```

```ini
# /etc/systemd/system/hostlint-agent.service
[Unit]
Description=hostlint agent (scan when the fleet server asks)
Wants=network-online.target
After=network-online.target

[Service]
ExecStart=/usr/local/bin/hostlint agent --server https://hostlint.example.org:8443 --pin sha256/... \
  --token-file /etc/hostlint/token --sign-key /etc/hostlint/signing-key --allow-profile kisa-2026
Restart=always
RestartSec=10
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
```

What the server can ask is one thing: a scan with a profile that **this host's own** `--allow-profile` list names
(one to eight built-in profiles), and at most once a minute. It cannot send waivers, parameters, paths or commands:
`hostlint.yaml` stays a file of the host, and the result goes back as `hostlint scan --push` sends it: the same
token, the same `--pin`, the same signature. An agent also refuses a request for a profile it does not allow, or one
that comes less than 45 seconds after its last scan, and it tells the server why. A server that is compromised can make
hosts scan more often, up to that limit; nothing else. The agent does not take `--pack`: a result of a policy pack is
not accepted by the server yet.

The host has to have sent a result once (`hostlint scan --push`), and its token has to be bound to it (`--host`): the
agent is the host's token, not a new kind of identity. Scheduled scans keep working next to it.

**Who may ask.** The button needs an **operator** token (`hostlint server token create --scope operator --any-host
--name ops`), or a dashboard session started with one: an operator reads like an `api` token and may also ask for
scans. A session started with an `api` token sees the host's agent but gets no button. The request is a JSON `POST
/api/v1/hosts/{id}/scan` with `{"profile": "kisa-2026"}`; from a browser session it is accepted only with an `Origin`
that is the server's own site, so a page of another site cannot make it (the session cookie is `SameSite=Strict` as
well); behind a reverse proxy, pass the `Host` header on unchanged. It answers `202` with the job, `409` when no agent of the host polled in the last two minutes or the agent does
not allow the profile, and `429` when a scan of that host was requested less than a minute ago or is still pending.
Every request is in the audit chain (`scan-requested`, with the token that made it and the address). The dashboard
shows the button only for a host whose agent is connected, and follows the request: waiting, scanning, arrived or
failed. A request nobody answers expires after ten minutes. `GET /api/v1/hosts/{id}/agent` has the same state.

## Results of policy packs

A scan made with a [policy pack](packs.md) is sent like any other (`hostlint scan --pack DIR -p x-acme-baseline --push ...`).
The server keeps the result as it is; the pack's profile appears in the dashboard's profile selector, and the host's page
names the pack (name, version, digest). The server does not read packs: a control's "what it checks" text is not there for
a pack's controls. At most eight packs are named by a result, each with a name, a version and its sha256 digest, and a
result of a pack's profile (an ID that starts with `x-`) has to name its pack. The pages count the results of one profile
together even when hosts ran different revisions of the pack: the digest of each scan tells them apart in its stored
document, not on the pages.

## Container images

A scan of an image archive (`hostlint scan --image-tar app.tar --push ...`, [docs/images.md](images.md)) is stored as an
**image**: an asset named by its repository, with no host ID, whose scans each record the tag and the image ID. The dashboard
lists images apart from hosts (**Images**, once there is one), and the fleet's numbers (overview, trend, matrix, controls,
stale and silent-host alerts) are those of the hosts. `GET /api/v1/hosts?kind=image` lists the images; every host entry has
a `kind`, and a scan row of an image its `imageRef` and `imageDigest`. A token for CI is bound to a prefix
(`server token create --host 'ghcr.io/acme/*'`); a prefix has its `*` at the end and at least three characters before it,
and it is an ingest token's alone (an agent speaks for one host). A name is a host or an image, never both.

## Signing people in with your company's identity

The dashboard signs a person in with a read token. To let people in with the sign-in your company already has
(Google, Entra ID, Okta, Keycloak: OIDC or SAML), put a reverse proxy that does the sign-in in front of the server
and let it pass the request on with a read token of its own. hostlint has no sign-in code of its own for this, on
purpose: a sign-in is the most attacked part of a web application ([ADR 0015](adr/0015-dashboard-sign-in.md)).

The server listens on a loopback address, behind the proxy:

```sh
hostlint server run --db /var/lib/hostlint/server.db --listen 127.0.0.1:8443 --plain-http --behind-proxy
hostlint server token create --db /var/lib/hostlint/server.db --scope api --name dashboard-proxy
```

An outline for nginx with [oauth2-proxy](https://oauth2-proxy.github.io/oauth2-proxy/) (`/etc/nginx/hostlint-token.conf`
holds `proxy_set_header Authorization "Bearer hlt_api_...";`, readable by root only and never shown to a browser):

```nginx
server {
    listen 443 ssl;
    server_name hostlint.example.org;
    # ssl_certificate ...

    # The hosts push with their own ingest tokens: no sign-in for this one path.
    location = /api/v1/results {
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_pass http://127.0.0.1:8443;
    }
    location /oauth2/ {
        proxy_pass http://127.0.0.1:4180;
        proxy_set_header Host $host;
    }
    location = /oauth2/auth {
        internal;
        proxy_pass http://127.0.0.1:4180;
        proxy_set_header Content-Length "";
        proxy_pass_request_body off;
    }
    location / {
        auth_request /oauth2/auth;
        error_page 401 = /oauth2/sign_in;
        include /etc/nginx/hostlint-token.conf;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_pass http://127.0.0.1:8443;
    }
}
```

What was tested is the server's side: a read token on every request makes the dashboard work without its sign-in
form, and the ingest path stays protected by its tokens. The proxy configuration is an outline of the usual settings of
your proxy: check it against its documentation. Things to know:

- Anyone who can reach the server's own address (another user of the machine) bypasses the sign-in: keep it on a loopback
  address, or on a host where only the proxy can reach it, and let nothing else listen next to it.
- The server's audit trail names the proxy's token, not the person; the proxy's access log has the person.
- Everyone who gets through the proxy can read everything: restrict who may sign in at the proxy (a group, a domain).
- Rotate the proxy's token like any other: `server token create`, change the file, `server token revoke`.

## Reading results

Hosts may scan with different profiles (`--profile`, `essentials`, a policy pack), so every number of the dashboard is of
**one profile**: the overview, the host list, the matrix and the control list take `?profile=ID` and, without it, use the
profile that most hosts scanned with (**a script that read these calls without `profile` before v0.19 now reads one profile: pass `?profile=all` for every profile added up, as before**). A host whose latest scan has none of its controls is not counted in the numbers (a silent host is still counted as stale, whatever it scanned with): the dashboard
says how many such hosts there are and marks them in the list. In the dashboard a selector in the sidebar picks the
profile (and remembers it) when there is more than one.

A read token (`--scope api`) lets a script or CI ask the server what it knows:

```sh
hostlint server token create --db server.db --name ci --scope api
curl --cacert tls.crt -H "Authorization: Bearer hlt_api_..." https://hostlint.example.org:8443/api/v1/overview
```

| Request | Answer |
|---|---|
| `GET /api/v1/profiles` | The profiles of the latest scans with the number of hosts of each, the one most hosts use (`default`), and their titles |
| `GET /api/v1/trend` | The fleet over the last days, one point a day, oldest first: hosts, hosts with a failing control, counts and pass rate as of that day (`?days=30`, 1 to 90). It is computed from the scans that are stored, so `server prune` changes the days it covers, and is served again for 30 seconds |
| `GET /api/v1/overview` | Hosts, hosts with a failing control, stale hosts, counts, the controls that fail on most hosts, recent regressions (`?staleDays=7`) |
| `GET /api/v1/hosts` | The hosts with the counts and score of their latest scan (`?q=`, `?status=failing\|stale`, `?sort=name\|score\|last`, `?limit=`, `?offset=`, `?format=csv`, `?kind=image` for the images); each host also has its `os`, `labels` (what its latest result says, bounded), `agentOnline` and a `trend` of the pass rate of its latest scans |
| `GET /api/v1/controls`, `GET /api/v1/controls/PROFILE/ID` | Every control with the status counts of the latest scans; one control with its hosts, and what it checks and how to fix it |
| `GET /api/v1/matrix` | The latest status of every control on every host, hosts that fail most first |
| `GET /api/v1/hosts/ID` | One host: its latest controls and its history |
| `GET /api/v1/scans/ID` | A stored result, exactly as received |
| `GET /api/v1/diff?old=ID&new=ID` | What changed between two scans, as `hostlint diff` |

### Dashboard sessions

The dashboard exchanges a read token for a session once: `POST /api/v1/login` with
`{"token": "hlt_api_..."}` (content type `application/json`) sets the `hl_session` cookie
(`HttpOnly`, `SameSite=Strict`, and `Secure` over TLS), `POST /api/v1/logout` ends it, and
`GET /api/v1/session` says whether it is still good. A session ends after 8 hours without use or 24
hours in all, or when its token is revoked or expires; a token keeps at most 20 sessions. The cookie
authenticates `GET` requests only. Logins are limited to 10 a minute per address. Behind a TLS proxy
(`--plain-http --behind-proxy`) the server trusts `X-Forwarded-Proto` for the `Secure` attribute and
the last `X-Forwarded-For` address as the client: only turn it on when a proxy really sits in front.

The score is PASS ÷ (PASS + FAIL + ERROR + MANUAL): results that are not decided count against it, and
NOT_APPLICABLE and WAIVED are left out of the ratio and listed beside it. A host is stale when it has
not reported for `staleDays`.

## Running it

A service with systemd (`/etc/systemd/system/hostlint-server.service`); the state directory is
created and owned by a throw-away user:

```ini
[Unit]
Description=hostlint server
After=network-online.target

[Service]
DynamicUser=yes
StateDirectory=hostlint
ExecStart=/usr/local/bin/hostlint server run --db /var/lib/hostlint/server.db --listen :8443
Restart=on-failure
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

Create tokens with `sudo systemd-run --pipe --property=DynamicUser=yes --property=StateDirectory=hostlint
hostlint server token create --db /var/lib/hostlint/server.db ...`, or run the command as root and
`chown` the database afterwards: the server refuses a database that other users can read.

In a container (a binary that includes the dashboard, an empty `scratch` image, a volume for the data
owned by uid 65532):

```dockerfile
FROM scratch
COPY hostlint /hostlint
VOLUME /data
EXPOSE 8443
USER 65532:65532
ENTRYPOINT ["/hostlint", "server", "run", "--db", "/data/hostlint.db", "--listen", ":8443"]
```

**Backup and retention.** `hostlint server backup FILE` writes a consistent copy while the server runs
(the file must not exist and is readable by you only); to restore, stop the server and put the copy at
`--db`. The server deletes scans older than `--retention` (400 days by default, `0` keeps everything)
once a day, and always keeps the latest scan of every host; `hostlint server prune --older-than 9600h`
does it once, and `hostlint server stats` shows what the database holds. Upgrading is replacing the
binary: the schema migrates when the server starts.

## What the server checks

- A valid token. An ingest token is bound to one host name (`--host`); the host ID in its first
  result is pinned, and a later result with another one is refused. `--any-host` makes a token that
  may speak for every host: an explicit choice.
- The result is well formed (the checks of `hostlint report`), at most 2 MiB (`--max-result-bytes`),
  500 controls and 5000 checks, with printable identifiers and a start time close to the server's
  clock. A scan ID is stored once per host; a known host name never gets a second host ID.
- Each token may send 60 results a minute (`--rate`); requests with a bad token are throttled by address.
- Everything is recorded in an audit table whose rows chain a hash of the previous row.
  `hostlint server verify` recomputes the chain and prints the last hash: keep it elsewhere to
  notice later changes.

## Signed results

A host can sign what it sends, so that a result is evidence of what that host's key said even if the
server that stores it is compromised later:

```sh
sudo hostlint key generate /etc/hostlint/sign.key      # once per host; prints the fingerprint
sudo HOSTLINT_TOKEN=hlt_ing_... hostlint scan --push https://hostlint.example.org:8443 \
  --sign-key /etc/hostlint/sign.key
```

The server registers the key at the host's first signed result (trust on first use). To rule out that
a stolen token registers someone else's key first, bind the token to the host's public key when you
create it: `hostlint server token create --name web-01 --host web-01 --key <public key>`; it then
accepts nothing but results signed with that key. From then on the server refuses that host's
results that are unsigned or signed with another key (a stolen token alone is no longer enough),
and the dashboard shows the host as signed with the key's fingerprint. `hostlint server verify` also
checks every stored scan against what the hash-chained audit log recorded when it was received (the
digest of the document and the key it was signed with) and against its signature, so a result changed in
the database afterwards, a signature that was removed or replaced, controls shown by the dashboard that
differ from the stored document, a scan moved to another host, and a scan with no ingest record are all
found. A host that signs does not go back in time: a signed result that does not start after the host's
latest scan is refused (a captured result cannot be replayed once the original was pruned), while a retry
of a stored scan is still answered as before. A host whose clock ran ahead by a few minutes has to wait until real time catches up (the server accepts start times at most five minutes ahead), and a scan that was delayed behind a newer one is not accepted any more. If a key was replaced on purpose (a re-installed machine), `hostlint server host reset-key ID --key
<new public key>` replaces the registered one at once (without `--key` it is forgotten, and until the next
signed result registers a key unsigned results are accepted). A token bound to the old key (`--key`) keeps asking for it: issue a new token for the host. The key file is refused if other users can read it.

## What it does not protect

The server is a store, not an authority. Whoever controls its database can change what it shows, and
can also replace both a stored result and its signature and key together: keep a copy of the key
fingerprints (`hostlint server host list`) and of the audit hash (`hostlint server verify`) somewhere
else to notice that. A stolen token can submit results for the host it is bound to unless that host
signs; a host whose own key is stolen can sign anything.

## Notifications

The server can post an event to a webhook when a host gets worse or stops reporting:

```sh
echo -n "a long random secret" > webhook.secret && chmod 600 webhook.secret
HOSTLINT_WEBHOOK_URL=https://hooks.example.com/services/XXX \
  hostlint server run --webhook-secret-file webhook.secret --stale-after 72h
```

- `regression`: a result in which a control is FAIL or ERROR that was not in the host's previous scan.
  It lists the controls (profile, ID, title, severity, old and new status), at most 20.
- `stale`: a host that has not reported for `--stale-after` (7 days by default), once for each of its
  latest scans.

The body is JSON with a `text` line that Slack, Mattermost and Discord's Slack-compatible endpoint show as it
is. It carries control IDs and statuses, never evidence. With `--webhook-secret-file` the body is signed:
`X-Hostlint-Signature-256: sha256=<hex HMAC-SHA256 of the body>`. The URL must be https (http only to a
loopback address); it is read from `--webhook-url` or `HOSTLINT_WEBHOOK_URL` (prefer the variable: a
webhook URL is a secret, and it is never logged). Redirects are not followed.

Delivery is at least once: an event is retried every 30 seconds until the webhook answers 2xx, and nothing
that happened before the webhook was enabled is reported (hosts that are silent already included). An answer
of 4xx (other than 408 and 429) means the event is refused for good: it is logged and dropped, so it does not
hold back the rest. Every event has an `id`, also sent as `X-Hostlint-Delivery`, that is the same for every
delivery of it: use it to drop repeats. A control that the host's previous scan did not have (a new rule or
profile) is not reported as a regression.

## Hosts

```sh
hostlint server host list   --db server.db
hostlint server host delete --db server.db 4 --yes
```

A known host name never gets a second host ID: a machine that was re-installed (its host ID changed) is
refused, and the answer says so. Delete the old host (and everything received from it, so make a
backup first) and the machine can start again under the same name. Deletions are audited.

## Tokens

```sh
hostlint server token list   --db server.db
hostlint server token revoke --db server.db 3
hostlint server token create --db server.db --name ci --any-host --expires-in 2160h
hostlint server token create --db server.db --name ops --scope operator --any-host   # reads, and asks agents for scans
```
