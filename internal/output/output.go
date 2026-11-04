// Package output renders scan results: a terminal table, the JSON result
// document, SARIF 2.1.0 and JUnit XML. It is the only package that may create
// files, and only the report file the user asked for (ADR 0004).
package output

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
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

// WriteFile renders res into the file at path, replacing it with mode 0644.
// This is the user-requested report file; nothing else is written. The report
// is rendered first and written to a new file beside path, which then
// replaces it: a failure leaves an earlier report intact, and a symbolic link
// at path is replaced, not followed.
func WriteFile(path string, res *engine.Result, format string, opts Options) error {
	var buf bytes.Buffer
	if err := Write(&buf, res, format, opts); err != nil {
		return err
	}
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return err
	}
	tmpPath := filepath.Join(filepath.Dir(path), ".hostlint-report-"+hex.EncodeToString(suffix[:]))
	tmp, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644) //nolint:gosec // G302/G304: beside the report path the user gave
	if err != nil {
		return err
	}
	if _, err := tmp.Write(buf.Bytes()); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return nil
}
