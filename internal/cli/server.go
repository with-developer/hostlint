package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/with-developer/hostlint/internal/engine"
	"github.com/with-developer/hostlint/internal/server"
	"github.com/with-developer/hostlint/profiles"
	"github.com/with-developer/hostlint/rules"
)

func newServerCommand() *cobra.Command {
	var dbPath string
	cmd := &cobra.Command{
		Use:   "server",
		Short: "Run the fleet server that collects scan results (early; see docs/adr/0010)",
		Long: `The server receives the scan results that hosts push with "hostlint push",
keeps them in a SQLite database and checks every request: a valid token, a bounded and
well-formed result, a host identity that fits the token. It has no connection to the hosts:
they send, it never asks.

The database is one file (--db). Tokens are made with "hostlint server token create" and
shown once; only their hash is stored.`,
	}
	cmd.PersistentFlags().StringVar(&dbPath, "db", "hostlint-server.db", "the server's SQLite database")
	cmd.AddCommand(newServerRunCommand(&dbPath), newServerTokenCommand(&dbPath), newServerVerifyCommand(&dbPath), newServerDemoCommand())
	return cmd
}

func newServerRunCommand(dbPath *string) *cobra.Command {
	var lc server.ListenConfig
	var maxBody int64
	var rate int
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Listen for results",
		Long: `Run listens over TLS. Without --tls-cert and --tls-key it makes a self-signed certificate next to
the database (tls.crt, tls.key) and prints its pin: give that to "hostlint push --pin". Plain
HTTP is only allowed on a loopback address, or behind a TLS proxy with --behind-proxy.`,
		Example: `  hostlint server token create --name web-01 --host web-01
  hostlint server run --listen :8443`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			store, err := server.OpenStore(*dbPath)
			if err != nil {
				return err
			}
			defer store.Close()
			lc.GeneratedDir = filepath.Dir(*dbPath)
			logger := slog.New(slog.NewTextHandler(cmd.ErrOrStderr(), nil))
			srv := server.New(server.Config{Store: store, MaxBody: maxBody, Rate: rate, Logger: logger, BehindProxy: lc.BehindProxy})
			out := cmd.OutOrStdout()
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
	return cmd
}

func newServerTokenCommand(dbPath *string) *cobra.Command {
	cmd := &cobra.Command{Use: "token", Short: "Create, list and revoke tokens"}

	var name, host, scope string
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
			tok, id, err := store.CreateCredential(cmd.Context(), scope, name, host, expires)
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
	fl.StringVar(&host, "host", "", "the host name the token may speak for")
	fl.BoolVar(&anyHost, "any-host", false, "a token for every host")
	fl.StringVar(&scope, "scope", server.ScopeIngest, "ingest (send results) or api (read; later)")
	fl.DurationVar(&expires, "expires-in", 0, "make the token expire after this long, such as 2160h (default: never)")
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
			return nil
		},
	}
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
		Example: `  hostlint server demo
  hostlint server demo --listen 127.0.0.1:9000`,
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
			srv := server.New(server.Config{Store: store, Rate: 600})
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
