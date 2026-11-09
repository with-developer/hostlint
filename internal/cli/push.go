package cli

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/with-developer/vmsctl/internal/engine"
	"github.com/with-developer/vmsctl/internal/output"
	"github.com/with-developer/vmsctl/internal/push"
	"github.com/with-developer/vmsctl/internal/signing"
)

func newPushCommand() *cobra.Command {
	var serverURL, pin, tokenFile, signKey string
	cmd := &cobra.Command{
		Use:   "push FILE...",
		Short: "Send scan results to a vmsctl server",
		Long: `Push sends result documents written by "vmsctl scan --format json" to a vmsctl server.
The token is read from the VMSCTL_TOKEN environment variable or from --token-file, never from
the command line. The server is trusted by its certificate, or by its public key with --pin (the
value "vmsctl server run" prints for a self-signed certificate).

A result is checked before it is sent, like "vmsctl report" does, so a file that is not a
result is refused here.`,
		Example: `  sudo vmsctl scan -f json -o result.json
  VMSCTL_TOKEN=hlt_ing_... vmsctl push result.json --server https://vmsctl.example.org:8443`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			token, err := readToken(tokenFile)
			if err != nil {
				return err
			}
			if serverURL == "" {
				return errors.New("--server is required")
			}
			var signer ed25519.PrivateKey
			if signKey != "" {
				if signer, err = signing.Load(signKey); err != nil {
					return err
				}
			}
			// Every file is tried: one that fails does not keep the others from being sent.
			var failed []string
			for _, name := range args {
				got, err := pushFile(cmd, name, serverURL, token, pin, signer)
				if err != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "vmsctl: %s: %v\n", name, err)
					failed = append(failed, name)
					continue
				}
				state := "received"
				if got.Duplicate {
					state = "already received"
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%s: %s (scan %d, %s)\n", name, state, got.Scan, got.Digest)
			}
			if len(failed) > 0 {
				return fmt.Errorf("%d of %d results were not sent", len(failed), len(args))
			}
			return nil
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&serverURL, "server", "", "the server's URL, such as https://vmsctl.example.org:8443")
	fl.StringVar(&pin, "pin", "", `trust this public key ("sha256/<base64>") instead of the system roots`)
	fl.StringVar(&tokenFile, "token-file", "", "read the token from this file")
	fl.StringVar(&signKey, "sign-key", "", "sign the result with this key (made with: vmsctl key generate)")
	return cmd
}

func pushFile(cmd *cobra.Command, name, serverURL, token, pin string, signer ed25519.PrivateKey) (*push.Response, error) {
	doc, err := os.ReadFile(name) //nolint:forbidigo,gosec // a result file the user named, not the scanned host (G304)
	if err != nil {
		return nil, err
	}
	if _, err := output.ReadResult(strings.NewReader(string(doc))); err != nil {
		return nil, err
	}
	return push.Send(cmd.Context(), doc, push.Options{URL: serverURL, Token: token, Pin: pin, SignKey: signer})
}

// readToken is the ingest token: from the file the user named, else from VMSCTL_TOKEN. It is
// never taken from the command line, where other users could see it.
func readToken(tokenFile string) (string, error) {
	token := env("TOKEN")
	if tokenFile != "" {
		data, err := os.ReadFile(tokenFile) //nolint:forbidigo,gosec // a file the user named, not the scanned host (G304)
		if err != nil {
			return "", err
		}
		token = strings.TrimSpace(string(data))
	}
	if token == "" {
		return "", errors.New("no token: set VMSCTL_TOKEN or use --token-file")
	}
	return token, nil
}

// pushScan sends the result of the scan that just ran, as JSON, whatever --format was.
func pushScan(cmd *cobra.Command, res *engine.Result, f scanFlags, token string, signer ed25519.PrivateKey) error {
	var doc bytes.Buffer
	if err := output.Write(&doc, res, "json", output.Options{}); err != nil {
		return err
	}
	got, err := push.Send(cmd.Context(), doc.Bytes(), push.Options{URL: f.pushURL, Token: token, Pin: f.pin, SignKey: signer, JobID: f.jobID})
	if err != nil {
		return fmt.Errorf("the result was not sent: %w", err)
	}
	state := "sent"
	if got.Duplicate {
		state = "already received"
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "result %s to %s (scan %d)\n", state, f.pushURL, got.Scan)
	return nil
}
