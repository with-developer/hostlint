// Package cli defines the hostlint command-line interface.
package cli

import (
	"context"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/with-developer/hostlint/internal/version"
)

// Process exit codes.
const (
	ExitOK    = 0 // success; nothing failed at or above the --fail-on threshold
	ExitFail  = 1 // the scan found failures (used by `hostlint scan`)
	ExitError = 2 // usage error or the command could not run
)

// Execute runs the CLI with args (without the program name) and returns the
// process exit code.
func Execute(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	cmd := newRootCommand()
	cmd.SetArgs(args)
	cmd.SetOut(stdout)
	cmd.SetErr(stderr)
	if err := cmd.ExecuteContext(ctx); err != nil {
		_, _ = fmt.Fprintf(stderr, "hostlint: %v\n", err)
		return ExitError
	}
	return ExitOK
}

func newRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:   "hostlint",
		Short: "Check a Linux host's security configuration against hardening baselines",
		Long: `hostlint checks a Linux host's security configuration against hardening
baselines and reports a result per control. It only observes: it never
changes the host it scans.`,
		Version:       version.Get().String(),
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.SetVersionTemplate("{{.Version}}\n")
	root.AddCommand(newVersionCommand())
	return root
}
