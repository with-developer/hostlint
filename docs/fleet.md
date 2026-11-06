# Fleet server (early)

> Phase 1 of [ADR 0010](adr/0010-fleet-server-and-dashboard.md): the server receives and stores
> results. The dashboard and the read API come next. Treat the interface as unstable.

Hosts scan themselves and **push** the result to a server. The server never connects to a host:
it cannot make one scan, run anything or read anything there.

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
