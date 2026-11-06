// Package cli defines the hostlint command-line interface.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/with-developer/hostlint/internal/version"
)

// Process exit codes.
const (
	ExitOK          = 0   // success; nothing failed at or above the --fail-on threshold
	ExitFail        = 1   // the scan found failures (used by `hostlint scan`)
	ExitError       = 2   // usage error, or the command could not run
	ExitInterrupted = 130 // interrupted by SIGINT or SIGTERM
)

// Execute runs the CLI with args (without the program name) and returns the
// process exit code. The command is interrupted when ctx is canceled.
func Execute(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	// Cobra's hidden __complete command appends debug output to the file named
	// by this variable; hostlint never writes to the host it runs on (ADR 0004).
	_ = os.Unsetenv("BASH_COMP_DEBUG_FILE")
	if args == nil {
		args = []string{} // cobra falls back to os.Args when given nil
	}

	cmd := newRootCommand()
	cmd.SetArgs(args)
	cmd.SetOut(stdout)
	cmd.SetErr(stderr)
	err := cmd.ExecuteContext(ctx)
	var findings *findingsError
	switch {
	case errors.As(err, &findings):
		// The scan finished and its result was written; a signal that came
		// afterwards does not make it interrupted.
		_, _ = fmt.Fprintf(stderr, "hostlint: %v\n", err)
		return ExitFail
	case err == nil:
		return ExitOK
	case ctx.Err() != nil && errors.Is(err, ctx.Err()):
		_, _ = fmt.Fprintln(stderr, "hostlint: interrupted")
		return ExitInterrupted
	default:
		_, _ = fmt.Fprintf(stderr, "hostlint: %v\n", err)
		return ExitError
	}
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
	root.SetHelpCommand(newHelpCommand())
	root.AddCommand(newScanCommand(), newReportCommand(), newVersionCommand())
	return root
}

// newHelpCommand replaces cobra's default help command, which exits 0 for an
// unknown topic.
func newHelpCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "help [command]",
		Short: "Help about any command",
		RunE: func(cmd *cobra.Command, args []string) error {
			target, rest, err := cmd.Root().Find(args)
			if err != nil || len(rest) > 0 {
				return fmt.Errorf("unknown help topic %q", strings.Join(args, " "))
			}
			return target.Help()
		},
	}
}
