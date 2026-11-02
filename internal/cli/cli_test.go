package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/with-developer/hostlint/internal/version"
)

func run(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = Execute(context.Background(), args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestExecute(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout string
		wantStderr string
	}{
		{name: "no args prints help", args: nil, wantCode: ExitOK, wantStdout: "Usage:"},
		{name: "version", args: []string{"version"}, wantCode: ExitOK, wantStdout: "hostlint "},
		{name: "--version flag", args: []string{"--version"}, wantCode: ExitOK, wantStdout: "hostlint "},
		{name: "version rejects args", args: []string{"version", "extra"}, wantCode: ExitError, wantStderr: "hostlint: "},
		{name: "unknown command", args: []string{"nope"}, wantCode: ExitError, wantStderr: `unknown command "nope"`},
		{name: "unknown flag", args: []string{"--nope"}, wantCode: ExitError, wantStderr: "unknown flag"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, stdout, stderr := run(t, tt.args...)
			if code != tt.wantCode {
				t.Errorf("exit code = %d, want %d (stderr: %q)", code, tt.wantCode, stderr)
			}
			if !strings.Contains(stdout, tt.wantStdout) {
				t.Errorf("stdout = %q, want it to contain %q", stdout, tt.wantStdout)
			}
			if !strings.Contains(stderr, tt.wantStderr) {
				t.Errorf("stderr = %q, want it to contain %q", stderr, tt.wantStderr)
			}
		})
	}
}

func TestVersionJSON(t *testing.T) {
	code, stdout, stderr := run(t, "version", "--json")
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
