// Package output renders scan results: a terminal table, the JSON result
// document, SARIF 2.1.0, JUnit XML, and an HTML report merging many hosts.
// It is the only package that may create files, and only the output file the
// user asked for (ADR 0004).
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/with-developer/hostlint/internal/engine"
)

// Formats lists the supported output formats.
var Formats = []string{"table", "json", "sarif", "junit"}

// Options control rendering.
type Options struct {
	// Color enables ANSI colors in the table format.
	Color bool
	// Verbose lists passing and not-applicable controls in the table too.
	Verbose bool
}

// Write renders res in format to w.
func Write(w io.Writer, res *engine.Result, format string, opts Options) error {
	switch format {
	case "table":
		return writeTable(w, res, opts)
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		return enc.Encode(res)
	case "sarif":
		return writeSARIF(w, res)
	case "junit":
		return writeJUnit(w, res)
	}
	return fmt.Errorf("unknown format %q (use %s)", format, strings.Join(Formats, ", "))
}

// ValidFormat reports whether format is supported.
func ValidFormat(format string) bool { return slices.Contains(Formats, format) }

// WriteFile renders res into the file at path, creating or replacing it with
// mode 0644. This is the user-requested report file; nothing else is written.
func WriteFile(path string, res *engine.Result, format string, opts Options) error {
	return writeFile(path, func(w io.Writer) error { return Write(w, res, format, opts) })
}

// writeFile creates or replaces the file at path, mode 0644, with what
// write writes. Only the output the user asked for is written this way.
func writeFile(path string, write func(io.Writer) error) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644) //nolint:gosec // G302/G304: the output path the user gave
	if err != nil {
		return err
	}
	if err := write(f); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
