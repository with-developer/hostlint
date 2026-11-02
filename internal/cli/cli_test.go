package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/with-developer/hostlint/internal/version"
)

func run(ctx context.Context, t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = Execute(ctx, args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestExecute(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout string // substring; "" means stdout must be empty
		wantStderr string // substring; "" means stderr must be empty
	}{
		{name: "no args prints help", args: nil, wantCode: ExitOK, wantStdout: "Usage:"},
		{name: "version", args: []string{"version"}, wantCode: ExitOK, wantStdout: "hostlint "},
		{name: "--version flag", args: []string{"--version"}, wantCode: ExitOK, wantStdout: "hostlint "},
		{name: "help topic", args: []string{"help", "version"}, wantCode: ExitOK, wantStdout: "Print version information"},
		{name: "unknown help topic", args: []string{"help", "nope"}, wantCode: ExitError, wantStderr: `unknown help topic "nope"`},
		{name: "help topic with extra args", args: []string{"help", "version", "x"}, wantCode: ExitError, wantStderr: "unknown help topic"},
		{name: "version rejects args", args: []string{"version", "extra"}, wantCode: ExitError, wantStderr: "hostlint: "},
		{name: "unknown command", args: []string{"nope"}, wantCode: ExitError, wantStderr: `unknown command "nope"`},
		{name: "unknown flag", args: []string{"--nope"}, wantCode: ExitError, wantStderr: "unknown flag"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, stdout, stderr := run(context.Background(), t, tt.args...)
			if code != tt.wantCode {
				t.Errorf("exit code = %d, want %d (stderr: %q)", code, tt.wantCode, stderr)
			}
			checkStream(t, "stdout", stdout, tt.wantStdout)
			checkStream(t, "stderr", stderr, tt.wantStderr)
		})
	}
}

func checkStream(t *testing.T, name, got, want string) {
	t.Helper()
	if want == "" {
		if got != "" {
			t.Errorf("%s = %q, want empty", name, got)
		}
		return
	}
	if !strings.Contains(got, want) {
		t.Errorf("%s = %q, want it to contain %q", name, got, want)
	}
}

func TestExecuteInterrupted(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	code, _, stderr := run(ctx, t, "version")
	if code != ExitInterrupted {
		t.Errorf("exit code = %d, want %d", code, ExitInterrupted)
	}
	if !strings.Contains(stderr, "interrupted") {
		t.Errorf("stderr = %q, want it to mention the interruption", stderr)
	}
}

// Cobra's completion error path appends to $BASH_COMP_DEBUG_FILE; hostlint
// must never create files on the host (ADR 0004).
func TestCompletionDoesNotWriteDebugFile(t *testing.T) {
	debugFile := filepath.Join(t.TempDir(), "comp-debug.log")
	t.Setenv("BASH_COMP_DEBUG_FILE", debugFile)

	// An unknown flag makes cobra report a completion error.
	if code, _, _ := run(context.Background(), t, "__complete", "version", "--bogus", ""); code != ExitOK {
		t.Fatalf("exit code = %d", code)
	}
	if _, err := os.Stat(debugFile); !os.IsNotExist(err) {
		t.Errorf("completion created %s (stat err: %v)", debugFile, err)
	}

	code, stdout, _ := run(context.Background(), t, "__complete", "ver")
	if code != ExitOK || !strings.Contains(stdout, "version") {
		t.Errorf("completion of %q = %q (exit %d), want it to offer version", "ver", stdout, code)
	}
}

func TestVersionJSON(t *testing.T) {
	code, stdout, stderr := run(context.Background(), t, "version", "--json")
	if code != ExitOK {
		t.Fatalf("exit code = %d, stderr: %q", code, stderr)
	}
	var got version.Info
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, stdout)
	}
	if got != version.Get() {
		t.Errorf("version --json = %+v, want %+v", got, version.Get())
	}
}
