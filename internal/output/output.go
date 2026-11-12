// Package output renders scan results: a terminal table, the JSON result
// document, SARIF 2.1.0, JUnit XML, Markdown for job summaries and comments, CSV for a spreadsheet, and an HTML report merging many hosts.
// It is the only package that may create files, and only the output file the
// user asked for (ADR 0004).
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

	"github.com/with-developer/vmsctl/internal/engine"
)

// Formats lists the supported output formats.
var Formats = []string{"table", "json", "sarif", "junit", "markdown", "csv"}

// Options control rendering.
type Options struct {
	// Color enables ANSI colors in the table format.
	Color bool
	// Verbose lists passing and not-applicable controls in the table too.
	Verbose bool
	// Lang is "ko" to show the Korean titles of controls and checks in the table and in Markdown (a title that has no Korean
	// one is shown in English); anything else, English. The JSON, SARIF and JUnit formats are not translated.
	Lang string
}

// Languages lists the values of Options.Lang.
var Languages = []string{"en", "ko"}

// titleIn is the title in the language of the report: the Korean one when it is asked for and there is one.
func titleIn(lang, title, titleKo string) string {
	if lang == "ko" && titleKo != "" {
		return titleKo
	}
	return title
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
	case "markdown":
		return writeMarkdown(w, res, opts.Lang)
	case "csv":
		return writeCSV(w, res)
	}
	return fmt.Errorf("unknown format %q (use %s)", format, strings.Join(Formats, ", "))
}

// ValidFormat reports whether format is supported.
func ValidFormat(format string) bool { return slices.Contains(Formats, format) }

// WriteFile renders res into the file at path, replacing it with mode 0644.
// This is the user-requested report file; nothing else is written.
func WriteFile(path string, res *engine.Result, format string, opts Options) error {
	return writeFile(path, func(w io.Writer) error { return Write(w, res, format, opts) })
}

// streams are the special files a report may be written to in place: a stream
// of the process or the null device. Any other device, pipe or socket is refused:
// replacing it would damage the host, and writing to it could too.
var streams = []string{"/dev/null", "/dev/stdout", "/dev/stderr", "/dev/tty"}

func isStream(path string) bool {
	if filepath.Clean(path) != path { // "/dev/fd/3/../x" names something else once opened
		return false
	}
	return slices.Contains(streams, path) || strings.HasPrefix(path, "/dev/fd/") || strings.HasPrefix(path, "/proc/self/fd/")
}

// writeFile replaces the file at path with what write writes: mode 0644 for a
// new file, the mode of the file it replaces otherwise. The output is rendered
// first and written to a new file beside path, which then replaces it: a failure
// leaves an earlier file intact, and a symbolic link at path is replaced, not
// followed. A stream (/dev/stdout, /dev/null) is written in place, and any other
// device, pipe or socket is refused.
func writeFile(path string, write func(io.Writer) error) error {
	var buf bytes.Buffer
	if err := write(&buf); err != nil {
		return err
	}
	mode := os.FileMode(0o644)
	if fi, err := os.Lstat(path); err == nil { //nolint:forbidigo // the report path the user gave, not the scanned host
		switch {
		case isStream(path):
			return writeInPlace(path, buf.Bytes())
		case fi.Mode().IsRegular():
			mode = fi.Mode().Perm()
		case fi.Mode()&os.ModeSymlink != 0:
			// replaced below, as before
		default:
			return fmt.Errorf("%s is not a regular file: refusing to replace it", path)
		}
	}
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return err
	}
	tmpPath := filepath.Join(filepath.Dir(path), ".vmsctl-report-"+hex.EncodeToString(suffix[:]))
	tmp, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode) //nolint:gosec // G302/G304: beside the output path the user gave
	if err != nil {
		return err
	}
	if _, err := tmp.Write(buf.Bytes()); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := tmp.Sync(); err != nil {
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

// writeInPlace writes to a stream the process was given, without creating or truncating it.
func writeInPlace(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0) //nolint:gosec // G304: a stream the user named for the report
	if err != nil {
		return err
	}
	// /dev/fd/N can be a regular file (stdout redirected to one): opening it
	// again starts at offset 0 and would overwrite its head.
	if fi, err := f.Stat(); err != nil || fi.Mode().IsRegular() || fi.IsDir() {
		_ = f.Close()
		if err != nil {
			return err
		}
		return fmt.Errorf("%s is a file, not a stream: write to standard output and redirect it, or name the file", path)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
