package cli

import (
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/with-developer/hostlint/internal/collect"
	"github.com/with-developer/hostlint/internal/config"
	"github.com/with-developer/hostlint/internal/engine"
	"github.com/with-developer/hostlint/internal/hostfs"
	"github.com/with-developer/hostlint/internal/output"
	"github.com/with-developer/hostlint/internal/version"
	"github.com/with-developer/hostlint/profiles"
	"github.com/with-developer/hostlint/rules"
)

// failOnLevels are the accepted --fail-on values, lowest first.
var failOnLevels = []string{"low", "medium", "high", "none"}

// findingsError means the scan ran and found failures at or above the
// --fail-on threshold; Execute turns it into ExitFail.
type findingsError struct {
	controls  int
	threshold string
}

func (e *findingsError) Error() string {
	return fmt.Sprintf("%d control(s) failed or could not be checked at severity %s or above", e.controls, e.threshold)
}

type scanFlags struct {
	profile, format, output, root, failOn, color, config string
	labels                                               []string
	verbose                                              bool
}

func newScanCommand() *cobra.Command {
	var f scanFlags
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Check this host, or a mounted root filesystem, against a profile",
		Long: `Scan checks the host it runs on (or, with --root, a filesystem mounted
elsewhere) against a profile and reports a result per control.

hostlint only reads: it never changes the host. Run it as root, or checks that
need protected files (such as /etc/shadow) report ERROR.`,
		Example: `  sudo hostlint scan
  sudo hostlint scan --format json --output web-01.json
  sudo hostlint scan --root /mnt/image --fail-on high`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runScan(cmd, f)
		},
	}
	fl := cmd.Flags()
	fl.StringVarP(&f.profile, "profile", "p", "kisa-2026", "profile to check against")
	fl.StringVarP(&f.format, "format", "f", "table", "output format: "+strings.Join(output.Formats, ", "))
	fl.StringVarP(&f.output, "output", "o", "", "write the report to this file instead of stdout")
	fl.StringVar(&f.root, "root", "/", "scan a filesystem mounted at this directory instead of the running system")
	fl.StringVar(&f.failOn, "fail-on", "low", "exit with status 1 when a control of this severity or higher fails or could not be checked (ERROR): "+strings.Join(failOnLevels, ", "))
	fl.StringArrayVar(&f.labels, "label", nil, "add a key=value label to the host in the report (repeatable)")
	fl.BoolVarP(&f.verbose, "verbose", "v", false, "also list passing and not-applicable controls in the table")
	fl.StringVar(&f.color, "color", "auto", "color the table: auto, always or never")
	fl.StringVar(&f.config, "config", "", "configuration file (default: ./hostlint.yaml, then /etc/hostlint/hostlint.yaml, if present)")
	return cmd
}

func runScan(cmd *cobra.Command, f scanFlags) error {
	if !output.ValidFormat(f.format) {
		return fmt.Errorf("unknown --format %q (use %s)", f.format, strings.Join(output.Formats, ", "))
	}
	if !slices.Contains(failOnLevels, f.failOn) {
		return fmt.Errorf("unknown --fail-on %q (use %s)", f.failOn, strings.Join(failOnLevels, ", "))
	}
	if f.color != "auto" && f.color != "always" && f.color != "never" {
		return fmt.Errorf("unknown --color %q (use auto, always or never)", f.color)
	}
	labels, err := parseLabels(f.labels)
	if err != nil {
		return err
	}

	content, err := engine.Load(rules.FS, profiles.FS)
	if err != nil {
		return fmt.Errorf("built-in content: %w", err)
	}
	opts := engine.Options{Labels: labels, Profile: f.profile}
	cfgPath, err := config.Find(f.config)
	if err != nil {
		return err
	}
	if cfgPath != "" {
		cfg, err := config.Load(cfgPath)
		if err != nil {
			return err
		}
		if cfg.Profile != "" && !cmd.Flags().Changed("profile") {
			opts.Profile = cfg.Profile
		}
		if err := cfg.Validate(content, opts.Profile); err != nil {
			return fmt.Errorf("%s:\n%w", cfgPath, err)
		}
		opts.Params, opts.Waivers = cfg.Engine()
		opts.Attestations = cfg.EngineAttestations()
	}
	e, err := engine.New(content, collect.All()...)
	if err != nil {
		return fmt.Errorf("built-in content: %w", err)
	}
	h, err := hostfs.Open(f.root)
	if err != nil {
		return err
	}
	defer h.Close()

	info := version.Get()
	opts.Tool = engine.ToolInfo{Name: "hostlint", Version: info.Version, Commit: info.Commit}
	res, err := e.Scan(cmd.Context(), h, opts)
	if err != nil {
		return err
	}
	if f.root != "/" && res.Host.OS.ID == "unknown" {
		// Without an operating system, absent files would read as passing
		// checks for a root that was never a system.
		return fmt.Errorf("--root %s: no operating system found there (no os-release); is it the root of a mounted system?", f.root)
	}

	outOpts := output.Options{Verbose: f.verbose, Color: useColor(f.color, f.output, cmd.OutOrStdout())}
	if f.output != "" {
		err = output.WriteFile(f.output, res, f.format, outOpts)
	} else {
		err = output.Write(cmd.OutOrStdout(), res, f.format, outOpts)
	}
	if err != nil {
		return err
	}
	if n := failedAtOrAbove(res, f.failOn); n > 0 {
		return &findingsError{controls: n, threshold: f.failOn}
	}
	return nil
}

func parseLabels(raw []string) (map[string]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	labels := map[string]string{}
	for _, l := range raw {
		k, v, ok := strings.Cut(l, "=")
		if !ok || k == "" {
			return nil, fmt.Errorf("--label %q: want key=value", l)
		}
		labels[k] = v
	}
	return labels, nil
}

// failedAtOrAbove counts FAIL and ERROR controls whose severity reaches
// threshold: a control that could not be checked is not a pass.
func failedAtOrAbove(res *engine.Result, threshold string) int {
	if threshold == "none" {
		return 0
	}
	minRank := engine.Severity(threshold).Rank()
	n := 0
	for _, c := range res.Controls {
		if (c.Status == engine.StatusFail || c.Status == engine.StatusError) && c.Severity.Rank() >= minRank {
			n++
		}
	}
	return n
}

// useColor decides whether the table gets ANSI colors: never when writing a
// file or when NO_COLOR is set, otherwise only on a terminal.
func useColor(mode, outputPath string, w io.Writer) bool {
	switch {
	case mode == "always":
		return true
	case mode == "never", outputPath != "", os.Getenv("NO_COLOR") != "", os.Getenv("TERM") == "dumb":
		return false
	}
	return isTerminal(w)
}

// isTerminal reports whether w is a terminal.
func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}
