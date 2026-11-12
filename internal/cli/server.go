package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/with-developer/vmsctl/internal/engine"
	"github.com/with-developer/vmsctl/internal/server"
	"github.com/with-developer/vmsctl/internal/signing"
	"github.com/with-developer/vmsctl/profiles"
	"github.com/with-developer/vmsctl/rules"
)

func newServerCommand() *cobra.Command {
	var dbPath string
	cmd := &cobra.Command{
		Use:   "server",
		Short: "Run the fleet server and dashboard that collect scan results (docs/fleet.md)",
		Long: `The server receives the scan results that hosts push with "vmsctl push",
keeps them in a SQLite database and checks every request: a valid token, a bounded and
well-formed result, a host identity that fits the token. It has no connection to the hosts:
they send, it never asks.

The database is one file (--db). Tokens are made with "vmsctl server token create" and
shown once; only their hash is stored.`,
		// Without --db the default file is used; a database that has the old default name is kept (ADR 0017).
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			if cmd.Flags().Changed("db") || cmd.Name() == "demo" { // demo keeps its data in memory
				return nil
			}
			picked, note, err := pickDefaultDB(dbPath, legacyDBPath)
			if err != nil {
				return err
			}
			if note != "" {
				fmt.Fprintln(cmd.ErrOrStderr(), note)
			}
			dbPath = picked
			return nil
		},
	}
	cmd.PersistentFlags().StringVar(&dbPath, "db", defaultDBPath, "the server's SQLite database")
	cmd.AddCommand(newServerRunCommand(&dbPath), newServerTokenCommand(&dbPath), newServerVerifyCommand(&dbPath), newServerDemoCommand(), newServerPruneCommand(&dbPath), newServerBackupCommand(&dbPath), newServerStatsCommand(&dbPath), newServerHostCommand(&dbPath))
	return cmd
}

func newServerRunCommand(dbPath *string) *cobra.Command {
	var lc server.ListenConfig
	var maxBody int64
	var rate int
	var retention, staleAfter time.Duration
	var webhookURL, webhookSecretFile, webhookLang string
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Listen for results",
		Long: `Run listens over TLS. Without --tls-cert and --tls-key it makes a self-signed certificate next to
the database (tls.crt, tls.key) and prints its pin: give that to "vmsctl push --pin". Plain
HTTP is only allowed on a loopback address, or behind a TLS proxy with --behind-proxy.`,
		Example: `  vmsctl server token create --name web-01 --host web-01
  vmsctl server run --listen :8443`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			webhookURL = strings.TrimSpace(firstNonEmpty(webhookURL, env("WEBHOOK_URL")))
			var hook *server.Webhook
			if webhookURL != "" {
				if err := server.ValidateWebhookURL(webhookURL); err != nil {
					return err
				}
				hook = &server.Webhook{URL: webhookURL}
				if webhookSecretFile != "" {
					secret, err := readSecretFile(webhookSecretFile)
					if err != nil {
						return err
					}
					hook.Secret = secret
				}
			} else if webhookSecretFile != "" {
				return errors.New("--webhook-secret-file needs --webhook-url")
			}
			lang, err := resolveLang(webhookLang)
			if err != nil {
				return fmt.Errorf("--webhook-lang: %w", err)
			}
			store, err := server.OpenStore(*dbPath)
			if err != nil {
				return err
			}
			defer store.Close()
			content, err := engine.Load(rules.FS, profiles.FS)
			if err != nil {
				return err
			}
			lc.GeneratedDir = filepath.Dir(*dbPath)
			logger := slog.New(slog.NewTextHandler(cmd.ErrOrStderr(), nil))
			srv := server.New(server.Config{Store: store, MaxBody: maxBody, Rate: rate, Logger: logger, BehindProxy: lc.BehindProxy, Content: content})
			out := cmd.OutOrStdout()
			if retention > 0 {
				go pruneLoop(cmd.Context(), store, retention, logger)
			}
			if hook != nil {
				n := &server.Notifier{Store: store, Hook: hook, StaleAfter: staleAfter, Lang: lang, Logger: logger}
				go n.Run(cmd.Context(), 30*time.Second)
			}
			return srv.Serve(cmd.Context(), lc, func(addr, pin string) {
				if pin != "" {
					fmt.Fprintf(out, "listening on https://%s\ncertificate pin: %s\n", addr, pin)
				} else {
					fmt.Fprintf(out, "listening on http://%s\n", addr)
				}
			})
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&lc.Addr, "listen", "127.0.0.1:8443", "address to listen on")
	fl.StringVar(&lc.CertFile, "tls-cert", "", "TLS certificate (PEM)")
	fl.StringVar(&lc.KeyFile, "tls-key", "", "TLS private key (PEM)")
	fl.BoolVar(&lc.PlainHTTP, "plain-http", false, "serve plain HTTP (loopback addresses only, unless --behind-proxy)")
	fl.BoolVar(&lc.BehindProxy, "behind-proxy", false, "allow --plain-http on a non-loopback address: a TLS proxy is in front")
	fl.Int64Var(&maxBody, "max-result-bytes", server.DefaultMaxBody, "the largest result accepted")
	fl.IntVar(&rate, "rate", 60, "results per minute one token may send")
	fl.StringVar(&webhookURL, "webhook-url", "", "post an event here when a host gets worse or stops reporting (https; or set VMSCTL_WEBHOOK_URL: the URL can be a secret)")
	fl.StringVar(&webhookSecretFile, "webhook-secret-file", "", "a file with the secret the webhook body is signed with (HMAC-SHA256 in "+server.HeaderWebhookSignature+")")
	fl.StringVar(&webhookLang, "webhook-lang", "", "the language of the one-line text of a webhook event: en or ko (default: VMSCTL_LANG, else en)")
	fl.DurationVar(&staleAfter, "stale-after", 7*24*time.Hour, "report a host that has not reported for this long (with --webhook-url)")
	fl.DurationVar(&retention, "retention", 400*24*time.Hour, "delete scans older than this once a day, except the latest scan of each host (0 keeps everything)")
	return cmd
}

func newServerTokenCommand(dbPath *string) *cobra.Command {
	cmd := &cobra.Command{Use: "token", Short: "Create, list and revoke tokens"}

	var name, host, scope, key string
	var expires time.Duration
	var anyHost bool
	create := &cobra.Command{
		Use:   "create",
		Short: "Create a token (shown once)",
		Long: `Create makes a token and prints it: it cannot be shown again. An ingest token is bound to one
host by --host: it can only send results of that host, and its host ID is pinned at its first use.
--any-host makes a token that may speak for every host; it is an explicit choice.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if scope == server.ScopeIngest && host == "" && !anyHost {
				return errors.New("an ingest token needs --host NAME, or --any-host to speak for every host")
			}
			if host != "" && anyHost {
				return errors.New("--host and --any-host exclude each other")
			}
			store, err := server.OpenStore(*dbPath)
			if err != nil {
				return err
			}
			defer store.Close()
			var opts []server.CredentialOption
			if key != "" {
				if scope != server.ScopeIngest || signing.Fingerprint(key) == "" {
					return errors.New("--key is the public key (base64) of an ingest token's host, as \"vmsctl key generate\" prints it")
				}
				opts = append(opts, server.WithKey(key))
			}
			tok, id, err := store.CreateCredential(cmd.Context(), scope, name, host, expires, opts...)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s\n", tok)
			fmt.Fprintf(cmd.ErrOrStderr(), "token %d created; this is the only time it is shown\n", id)
			return nil
		},
	}
	fl := create.Flags()
	fl.StringVar(&name, "name", "", "a name to recognize the token by (required)")
	fl.StringVar(&host, "host", "", "the host name the token may speak for; an ingest token may be bound to a prefix of names, such as 'ghcr.io/acme/*' for the CI of an organization")
	fl.BoolVar(&anyHost, "any-host", false, "a token for every host")
	fl.StringVar(&scope, "scope", server.ScopeIngest, "ingest (send results), api (read) or operator (read, and ask agents for scans)")
	fl.DurationVar(&expires, "expires-in", 0, "make the token expire after this long, such as 2160h (default: never)")
	fl.StringVar(&key, "key", "", "bind the token to this public key (base64): it only accepts results signed with it")
	_ = create.MarkFlagRequired("name")

	list := &cobra.Command{
		Use:   "list",
		Short: "List tokens",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			store, err := server.OpenStore(*dbPath)
			if err != nil {
				return err
			}
			defer store.Close()
			creds, err := store.ListCredentials(cmd.Context())
			if err != nil {
				return err
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tSCOPE\tNAME\tPREFIX\tHOST\tLAST USED\tSTATE")
			for _, c := range creds {
				state := "active"
				switch {
				case c.RevokedAt != "":
					state = "revoked"
				case c.ExpiresAt != "":
					state = "expires " + c.ExpiresAt
				}
				host := c.BoundName
				if host == "" {
					host = "(any)"
				}
				fmt.Fprintf(tw, "%d\t%s\t%s\t%s…\t%s\t%s\t%s\n", c.ID, c.Scope, oneLineCLI(c.Name), c.Prefix, oneLineCLI(host), orDash(c.LastUsedAt), state)
			}
			return tw.Flush()
		},
	}
	revoke := &cobra.Command{
		Use:   "revoke ID",
		Short: "Revoke a token",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := strconv.ParseInt(args[0], 10, 64)
			if err != nil {
				return fmt.Errorf("%q is not a token ID", args[0])
			}
			store, err := server.OpenStore(*dbPath)
			if err != nil {
				return err
			}
			defer store.Close()
			ok, err := store.RevokeCredential(cmd.Context(), id)
			if err != nil {
				return err
			}
			if !ok {
				return fmt.Errorf("no active token %d", id)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "token %d revoked\n", id)
			return nil
		},
	}
	cmd.AddCommand(create, list, revoke)
	return cmd
}

func newServerVerifyCommand(dbPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "verify",
		Short: "Check the audit chain of the database",
		Long: `Verify recomputes the hash chain of the audit table. It prints the hash of the last row: keep
it elsewhere, and a later run shows whether history was changed or cut off.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			store, err := server.OpenStore(*dbPath)
			if err != nil {
				return err
			}
			defer store.Close()
			rows, last, err := store.VerifyAudit(context.WithoutCancel(cmd.Context()))
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "audit chain OK: %d rows, last hash %s\n", rows, last)
			rep, err := store.VerifySignatures(cmd.Context())
			if err != nil {
				return err
			}
			if !rep.OK() {
				var problems []string
				if len(rep.Mismatched) > 0 {
					problems = append(problems, fmt.Sprintf("%d stored scans differ from what was recorded when they were received (document, signature or key)%s: the database was changed afterwards", len(rep.Mismatched), idList(rep.Mismatched)))
				}
				if len(rep.Derived) > 0 {
					problems = append(problems, fmt.Sprintf("%d scans show other controls or another host than their stored document says%s", len(rep.Derived), idList(rep.Derived)))
				}
				if len(rep.Unrecorded) > 0 {
					problems = append(problems, fmt.Sprintf("%d scans have no ingest record in the audit chain%s", len(rep.Unrecorded), idList(rep.Unrecorded)))
				}
				return errors.New(strings.Join(problems, "; "))
			}
			fmt.Fprintf(cmd.OutOrStdout(), "signatures OK: %d signed scans verify, %d are unsigned\n", rep.Signed, rep.Unsigned)
			return nil
		},
	}
}

// idList shows up to twenty scan IDs.
func idList(ids []int64) string {
	shown := ids[:min(len(ids), 20)]
	parts := make([]string, len(shown))
	for i, id := range shown {
		parts[i] = strconv.FormatInt(id, 10)
	}
	more := ""
	if len(ids) > len(shown) {
		more = ", …"
	}
	return " (scan IDs " + strings.Join(parts, ", ") + more + ")"
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// oneLineCLI keeps a name from a database on one line of the terminal.
func oneLineCLI(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
}

func newServerDemoCommand() *cobra.Command {
	var listen, profile string
	cmd := &cobra.Command{
		Use:   "demo",
		Short: "Try the dashboard with a made-up fleet (nothing is scanned or written)",
		Long: `Demo starts a server on a loopback address with generated results: twelve invented hosts with
two weeks of scans each, built from the real controls of the profile, so the dashboard has something
to show. The data lives in memory and is gone when the command ends. It prints a read token to sign in with.`,
		Example: `  vmsctl server demo
  vmsctl server demo --listen 127.0.0.1:9000`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			content, err := engine.Load(rules.FS, profiles.FS)
			if err != nil {
				return err
			}
			store, err := server.OpenStore(":memory:")
			if err != nil {
				return err
			}
			defer store.Close()
			n, err := server.SeedDemo(cmd.Context(), store, content, profile, time.Now())
			if err != nil {
				return err
			}
			token, _, err := store.CreateCredential(cmd.Context(), server.ScopeAPI, "demo", "", 0)
			if err != nil {
				return err
			}
			srv := server.New(server.Config{Store: store, Rate: 600, Content: content})
			out := cmd.OutOrStdout()
			return srv.Serve(cmd.Context(), server.ListenConfig{Addr: listen, PlainHTTP: true}, func(addr, _ string) {
				fmt.Fprintf(out, "demo fleet: 12 made-up hosts, %d results\nopen http://%s and sign in with this read token:\n\n  %s\n\n(Ctrl-C ends the demo; the data is gone with it)\n", n, addr, token)
			})
		},
	}
	cmd.Flags().StringVar(&listen, "listen", "127.0.0.1:8443", "loopback address to listen on")
	cmd.Flags().StringVar(&profile, "profile", "kisa-2026", "the profile whose controls the demo uses")
	return cmd
}

// pruneLoop applies the retention once a day while the server runs.
func pruneLoop(ctx context.Context, store *server.Store, retention time.Duration, logger *slog.Logger) {
	for {
		if n, err := store.Prune(ctx, retention); err != nil {
			logger.Error("prune", "error", err)
		} else if n > 0 {
			logger.Info("pruned old scans", "scans", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(24 * time.Hour):
		}
	}
}

func newServerPruneCommand(dbPath *string) *cobra.Command {
	var olderThan time.Duration
	cmd := &cobra.Command{
		Use:   "prune",
		Short: "Delete old scans (the latest scan of every host is kept)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			store, err := server.OpenStore(*dbPath)
			if err != nil {
				return err
			}
			defer store.Close()
			n, err := store.Prune(cmd.Context(), olderThan)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%d scans deleted\n", n)
			return nil
		},
	}
	cmd.Flags().DurationVar(&olderThan, "older-than", 400*24*time.Hour, "delete scans received longer ago than this, such as 9600h")
	return cmd
}

func newServerBackupCommand(dbPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "backup FILE",
		Short: "Write a consistent copy of the database (safe while the server runs)",
		Long: `Backup writes a copy of the database to FILE, which must not exist yet, readable by you only.
It uses SQLite's online copy, so the server can keep running. To restore, stop the server and put the
copy where --db points.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := server.OpenStore(*dbPath)
			if err != nil {
				return err
			}
			defer store.Close()
			if err := store.Backup(cmd.Context(), args[0]); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "backup written to %s\n", args[0])
			return nil
		},
	}
}

func newServerStatsCommand(dbPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "stats",
		Short: "Show what the database holds",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			store, err := server.OpenStore(*dbPath)
			if err != nil {
				return err
			}
			defer store.Close()
			st, err := store.Stats(cmd.Context())
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "hosts: %d\nscans: %d (%s to %s)\nactive tokens: %d\n", st.Hosts, st.Scans, orDash(st.Oldest), orDash(st.Newest), st.Credentials)
			return nil
		},
	}
}

func newServerHostCommand(dbPath *string) *cobra.Command {
	cmd := &cobra.Command{Use: "host", Short: "List and delete hosts"}
	list := &cobra.Command{
		Use:   "list",
		Short: "List the hosts the server knows",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			store, err := server.OpenStore(*dbPath)
			if err != nil {
				return err
			}
			defer store.Close()
			hosts, err := store.HostList(cmd.Context())
			if err != nil {
				return err
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tNAME\tHOST ID\tLAST SCAN\tKEY")
			for _, h := range hosts {
				fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\n", h.ID, oneLineCLI(h.Name), orDash(oneLineCLI(h.HostID)), orDash(h.LastScanAt), orDash(h.KeyFingerprint))
			}
			return tw.Flush()
		},
	}
	var newKey string
	reset := &cobra.Command{
		Use:   "reset-key ID",
		Short: "Replace the signing key registered for a host",
		Long: `A host that signs its results keeps signing with the same key. If its key was replaced on purpose
(a re-installed machine), give the new public key with --key (the one "vmsctl key generate" printed):
it replaces the registered one at once. Without --key the registered key is forgotten and the next signed
result registers a key, which leaves a window in which unsigned results are accepted.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := strconv.ParseInt(args[0], 10, 64)
			if err != nil || id < 1 {
				return fmt.Errorf("%q is not a host ID (see: vmsctl server host list)", args[0])
			}
			store, err := server.OpenStore(*dbPath)
			if err != nil {
				return err
			}
			defer store.Close()
			ok, err := store.ResetHostKey(cmd.Context(), id, newKey)
			if err != nil {
				return err
			}
			if !ok {
				return fmt.Errorf("host %d has no registered key", id)
			}
			if newKey == "" {
				fmt.Fprintf(cmd.OutOrStdout(), "the key of host %d was forgotten: until its next signed result registers a key, unsigned results are accepted (prefer --key)\n", id)
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), "the key of host %d was replaced\n", id)
			}
			return nil
		},
	}
	var yes bool
	del := &cobra.Command{
		Use:   "delete ID",
		Short: "Delete a host and all the results received from it",
		Long: `Delete removes a host and every scan of it. It is for a machine that was re-installed (its host ID
changed, so the server refuses its results under the old name), or one that was retired. It cannot
be undone: make a backup first, and pass --yes to confirm.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := strconv.ParseInt(args[0], 10, 64)
			if err != nil || id < 1 {
				return fmt.Errorf("%q is not a host ID (see: vmsctl server host list)", args[0])
			}
			if !yes {
				return errors.New("this deletes the host and all its results for good: add --yes to confirm")
			}
			store, err := server.OpenStore(*dbPath)
			if err != nil {
				return err
			}
			defer store.Close()
			ok, err := store.DeleteHost(cmd.Context(), id)
			if err != nil {
				return err
			}
			if !ok {
				return fmt.Errorf("no host %d", id)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "host %d deleted\n", id)
			return nil
		},
	}
	del.Flags().BoolVar(&yes, "yes", false, "confirm the deletion")
	reset.Flags().StringVar(&newKey, "key", "", "the host's new public key (base64)")
	cmd.AddCommand(list, del, reset)
	return cmd
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// readSecretFile reads a secret from a file only its owner can read.
func readSecretFile(path string) ([]byte, error) {
	f, err := os.Open(path) //nolint:forbidigo,gosec // a file the user named, not the scanned host (G304)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s is readable by other users: chmod 600 it", path)
	}
	if fi.Size() > 4096 {
		return nil, fmt.Errorf("%s is larger than 4096 bytes: a secret of that size is a mistake", path)
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	secret := bytes.TrimSpace(data)
	if len(secret) == 0 {
		return nil, fmt.Errorf("%s is empty", path)
	}
	return secret, nil
}
