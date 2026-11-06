package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/with-developer/hostlint/internal/engine"
	"github.com/with-developer/hostlint/internal/output"
	"github.com/with-developer/hostlint/internal/version"
)

func newReportCommand() *cobra.Command {
	var out, title string
	cmd := &cobra.Command{
		Use:   "report FILE...",
		Short: "Merge JSON results from many hosts into one HTML report",
		Long: `Report merges result documents written by "hostlint scan --format json"
into one self-contained HTML file. The file makes no network requests and needs
no server, so it can be mailed to an auditor or archived.

When a host was scanned more than once, the report shows the newest result and
says which ones it left out. Results with an unknown schema version, or that are
not well formed, are rejected.`,
		Example: `  hostlint report results/*.json --output report.html
  hostlint report --title "Q4 audit" web-*.json db-*.json -o q4.html`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runReport(cmd, args, out, title)
		},
	}
	fl := cmd.Flags()
	fl.StringVarP(&out, "output", "o", "", "write the report to this file (default: standard output, if it is not a terminal)")
	fl.StringVar(&title, "title", "", `title of the report (default "hostlint report")`)
	return cmd
}

func runReport(cmd *cobra.Command, files []string, out, title string) error {
	if out == "" && isTerminal(cmd.OutOrStdout()) {
		return errors.New("the report is an HTML file: name it with --output, or redirect standard output")
	}
	inputs := make([]output.ReportInput, 0, len(files))
	seen := map[string]bool{}
	var unique []string
	for _, name := range files {
		// The same file named twice (an overlapping glob) is one input.
		key := name
		if abs, err := filepath.Abs(name); err == nil {
			key = abs
		}
		if !seen[key] {
			seen[key] = true
			unique = append(unique, name)
		}
	}
	files = unique
	for _, name := range files {
		res, err := readResultFile(name)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		inputs = append(inputs, output.ReportInput{Name: displayName(name, files), Result: res})
	}
	opts := output.ReportOptions{Title: title, Tool: version.Get().Version, Now: time.Now()}
	if out == "" {
		return output.WriteReport(cmd.OutOrStdout(), inputs, opts)
	}
	return output.WriteReportFile(out, inputs, opts)
}

// displayName is how a result file is named in the report: its file name,
// or the path as given when another file has the same name.
func displayName(name string, all []string) string {
	same := 0
	for _, other := range all {
		if filepath.Base(other) == filepath.Base(name) {
			same++
		}
	}
	if same > 1 {
		return filepath.Clean(name)
	}
	return filepath.Base(name)
}

// readResultFile reads a result document the user named. It is hostlint's
// own output, read on the machine making the report, not a file of a
// scanned host.
func readResultFile(name string) (*engine.Result, error) {
	f, err := os.Open(name) //nolint:forbidigo,gosec // a result file the user named, not the scanned host (G304)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return output.ReadResult(f)
}
