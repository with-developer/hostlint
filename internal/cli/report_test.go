package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReportCommand(t *testing.T) {
	ctx := context.Background()
	fixtures := filepath.Join("..", "output", "testdata", "report")
	web, db := filepath.Join(fixtures, "web-01.json"), filepath.Join(fixtures, "db-01.json")
	dir := t.TempDir()

	out := filepath.Join(dir, "report.html")
	if code, stdout, stderr := run(ctx, t, "report", web, db, "--output", out, "--title", "Q4 audit"); code != ExitOK || stdout != "" || stderr != "" {
		t.Fatalf("code %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	page, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(page), "<!doctype html>") || !strings.Contains(string(page), "<title>Q4 audit</title>") {
		t.Errorf("unexpected report:\n%.300s", page)
	}

	// Standard output, when it is not a terminal.
	if code, stdout, _ := run(ctx, t, "report", web); code != ExitOK || !strings.Contains(stdout, `id="report-data"`) {
		t.Errorf("code %d, stdout %.200q", code, stdout)
	}

	// The same file named twice (an overlapping glob) is one input, not a second scan.
	if code, stdout, _ := run(ctx, t, "report", web, filepath.Join(fixtures, "..", "report", "web-01.json")); code != ExitOK || strings.Contains(stdout, "scanned more than once") {
		t.Errorf("code %d; the same file counted as two scans", code)
	}

	bad := filepath.Join(dir, "v2.json")
	if err := os.WriteFile(bad, []byte(`{"schemaVersion": 2}`), 0o644); err != nil {
		t.Fatal(err)
	}
	failing := filepath.Join(dir, "failing.html")
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"no files", []string{"report"}, "requires at least 1 arg"},
		{"missing file", []string{"report", filepath.Join(dir, "nope.json")}, "nope.json"},
		{"unknown schema version", []string{"report", web, bad, "-o", failing}, "v2.json: result schema version 2 is not supported"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, _, stderr := run(ctx, t, tt.args...)
			if code != ExitError || !strings.Contains(stderr, tt.want) {
				t.Errorf("code %d, stderr %q; want %q", code, stderr, tt.want)
			}
		})
	}
	if _, err := os.Stat(failing); err == nil {
		t.Error("a failed report still wrote its file")
	}
}

// Result files with the same name are told apart by their paths.
func TestDisplayName(t *testing.T) {
	all := []string{"a/result.json", "b/result.json", "c/web.json"}
	if got := displayName("a/result.json", all); got != "a/result.json" {
		t.Errorf("same name: %q", got)
	}
	if got := displayName("c/web.json", all); got != "web.json" {
		t.Errorf("unique name: %q", got)
	}
}
