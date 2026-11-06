package cli

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/with-developer/hostlint/internal/output"
	"github.com/with-developer/hostlint/internal/push"
)

func newPushCommand() *cobra.Command {
	var serverURL, pin, tokenFile string
	cmd := &cobra.Command{
		Use:   "push FILE...",
		Short: "Send scan results to a hostlint server",
		Long: `Push sends result documents written by "hostlint scan --format json" to a hostlint server.
The token is read from the HOSTLINT_TOKEN environment variable or from --token-file, never from
the command line. The server is trusted by its certificate, or by its public key with --pin (the
value "hostlint server run" prints for a self-signed certificate).

A result is checked before it is sent, like "hostlint report" does, so a file that is not a
result is refused here.`,
		Example: `  sudo hostlint scan -f json -o result.json
  HOSTLINT_TOKEN=hlt_ing_... hostlint push result.json --server https://hostlint.example.org:8443`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			token := os.Getenv("HOSTLINT_TOKEN")
			if tokenFile != "" {
				data, err := os.ReadFile(tokenFile) //nolint:forbidigo,gosec // a file the user named, not the scanned host (G304)
				if err != nil {
					return err
				}
				token = strings.TrimSpace(string(data))
			}
			if token == "" {
				return errors.New("no token: set HOSTLINT_TOKEN or use --token-file")
			}
			if serverURL == "" {
				return errors.New("--server is required")
			}
			for _, name := range args {
				doc, err := os.ReadFile(name) //nolint:forbidigo,gosec // a result file the user named, not the scanned host (G304)
				if err != nil {
					return err
				}
				if _, err := output.ReadResult(strings.NewReader(string(doc))); err != nil {
					return fmt.Errorf("%s: %w", name, err)
				}
				got, err := push.Send(cmd.Context(), doc, push.Options{URL: serverURL, Token: token, Pin: pin})
				if err != nil {
					return fmt.Errorf("%s: %w", name, err)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%s: received (scan %d, %s)\n", name, got.Scan, got.Digest)
			}
			return nil
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&serverURL, "server", "", "the server's URL, such as https://hostlint.example.org:8443")
	fl.StringVar(&pin, "pin", "", `trust this public key ("sha256/<base64>") instead of the system roots`)
	fl.StringVar(&tokenFile, "token-file", "", "read the token from this file")
	return cmd
}
