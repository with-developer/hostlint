# Fleet server (early)

> Phase 1 of [ADR 0010](adr/0010-fleet-server-and-dashboard.md): the server receives and stores
> results and answers read requests. The dashboard comes next. Treat the interface as unstable.

Hosts scan themselves and **push** the result to a server. The server never connects to a host:
it cannot make one scan, run anything or read anything there.

## Dashboard

`hostlint server run` serves a web dashboard at its address when the binary was built with it: the
release binaries are, and a source build uses `make build-web` (Node 22). A binary from `go install`
has the API only and says so at `/`. Sign in with a read token (`hostlint server token create --scope
api`): the dashboard shows the fleet overview (pass rate, hosts with a failing control, hosts that
stopped reporting, the controls that fail most, recent regressions), the host list (search, filters,
sorting, CSV export), a list of controls (and for each one what it checks, why it matters, how to fix it and the hosts that fail it), a matrix of every control on every host, and for each host its controls with the evidence of every check, its history and a
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

On each host:

```sh
sudo hostlint scan --format json --output result.json
HOSTLINT_TOKEN=hlt_ing_... hostlint push result.json \
  --server https://hostlint.example.org:8443 --pin sha256/JSofaoL4gyTKBhYAk1QjTRDCC93WqgtDa3AKhMzYk2U=
```

The token comes from `HOSTLINT_TOKEN` or `--token-file`, never from the command line. With a
certificate from a public CA, leave `--pin` out. Run both steps from cron or a systemd timer.
Sending a result the server already has is not an error.

## Reading results

A read token (`--scope api`) lets a script or CI ask the server what it knows:

```sh
hostlint server token create --db server.db --name ci --scope api
curl --cacert tls.crt -H "Authorization: Bearer hlt_api_..." https://hostlint.example.org:8443/api/v1/overview
```

| Request | Answer |
|---|---|
| `GET /api/v1/overview` | Hosts, hosts with a failing control, stale hosts, counts, the controls that fail on most hosts, recent regressions (`?staleDays=7`) |
| `GET /api/v1/hosts` | The hosts with the counts and score of their latest scan (`?q=`, `?status=failing\|stale`, `?sort=name\|score\|last`, `?limit=`, `?offset=`, `?format=csv`) |
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

## What it does not protect

The server is a store, not an authority. Whoever controls its database can change what it shows,
and a stolen token can submit results for the host it is bound to. Signed results are planned. Until
then, the stored records are only as trustworthy as the server.

## Tokens

```sh
hostlint server token list   --db server.db
hostlint server token revoke --db server.db 3
hostlint server token create --db server.db --name ci --any-host --expires-in 2160h
```
