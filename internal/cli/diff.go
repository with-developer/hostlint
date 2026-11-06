package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/with-developer/hostlint/internal/output"
)

type diffFlags struct {
	format, out, color string
	failOnRegression   bool
}

func newDiffCommand() *cobra.Command {
	var f diffFlags
	cmd := &cobra.Command{
		Use:   "diff OLD.json NEW.json",
		Short: "Show what changed between two scans of a host",
		Long: `Diff compares two result documents written by "hostlint scan --format json" and
lists the controls whose status changed: regressed (FAIL or ERROR now, and not before),
fixed, changed in another way, and controls found in only one of the results. For every
control it also lists the checks that changed.

The first file is the older scan. Results of different hosts or of different profile
revisions are compared too, with a note.`,
		Example: `  hostlint scan -f json -o before.json
  hostlint scan -f json -o after.json
  hostlint diff before.json after.json

  # CI: fail when a control got worse
  hostlint diff baseline.json current.json --fail-on-regression`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDiff(cmd, args, f)
		},
	}
	fl := cmd.Flags()
	fl.StringVarP(&f.format, "format", "f", "table", "output format: table or json")
	fl.StringVarP(&f.out, "output", "o", "", "write the diff to this file (default: standard output)")
	fl.StringVar(&f.color, "color", "auto", "color the table: auto, always or never")
	fl.BoolVar(&f.failOnRegression, "fail-on-regression", false, "exit with status 1 when a control regressed")
	return cmd
}

func runDiff(cmd *cobra.Command, files []string, f diffFlags) error {
	if f.format != "table" && f.format != "json" {
		return fmt.Errorf("unknown --format %q (use table or json)", f.format)
	}
	if f.color != "auto" && f.color != "always" && f.color != "never" {
		return fmt.Errorf("unknown --color %q (use auto, always or never)", f.color)
	}
	older, err := readResultFile(files[0])
	if err != nil {
		return fmt.Errorf("%s: %w", files[0], err)
	}
	newer, err := readResultFile(files[1])
	if err != nil {
		return fmt.Errorf("%s: %w", files[1], err)
	}
	d := output.DiffResults(files[0], older, files[1], newer)
	opts := output.Options{Color: useColor(f.color, f.out, cmd.OutOrStdout())}
	if f.out != "" {
		err = output.WriteDiffFile(f.out, d, f.format, opts)
	} else {
		err = output.WriteDiff(cmd.OutOrStdout(), d, f.format, opts)
	}
	if err != nil {
		return err
	}
	if f.failOnRegression && len(d.Regressed) > 0 {
		return &findingsError{regressions: len(d.Regressed)}
	}
	return nil
}
