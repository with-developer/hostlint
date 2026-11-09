package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/with-developer/vmsctl/internal/signing"
)

func newKeyCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "key",
		Short: "Make the key a host signs its results with",
		Long: `A host can sign the results it sends to a vmsctl server ("vmsctl scan --push ... --sign-key FILE").
The server registers the key at the host's first signed result and from then on refuses results of that
host that are unsigned or signed with another key, and "vmsctl server verify" can check that a stored
result is still the document that was signed. Keep the key file on the host, readable by root only.`,
	}
	cmd.AddCommand(&cobra.Command{
		Use:     "generate FILE",
		Short:   "Make a signing key (Ed25519) and write its private half to FILE",
		Example: "  sudo vmsctl key generate /etc/vmsctl/sign.key",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			pub, err := signing.Generate(args[0])
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "key written to %s (mode 0600)\npublic key: %s\nfingerprint: %s\n", args[0], pub, signing.Fingerprint(pub))
			return nil
		},
	})
	return cmd
}
