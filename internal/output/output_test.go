package output

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/with-developer/hostlint/internal/engine"
)

var update = flag.Bool("update", false, "rewrite the golden files")

// sampleResult covers every status, evidence with and without sources, and a
// parameterized check.
func sampleResult() *engine.Result {
	digest := "sha256:" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	ev := func(key, text, source string) engine.Evidence {
		return engine.Evidence{Key: key, Text: text, Source: source}
	}
	return &engine.Result{
		SchemaVersion: 1,
		Scan: engine.ScanInfo{
			ID: "019a43c2-6f0e-7b51-9b5f-3c2e8d1a4f10", StartedAt: "2026-11-02T12:00:00Z", FinishedAt: "2026-11-02T12:00:01Z",
			Tool: engine.ToolInfo{Name: "hostlint", Version: "v0.1.0"}, Target: engine.TargetInfo{Kind: "host", Root: "/"},
			Privileges: engine.Privileges{EUID: 0},
		},
		Host:     engine.HostInfo{Hostname: "web-01", OS: engine.OSInfo{ID: "ubuntu", VersionID: "24.04", Family: "debian", Name: "Ubuntu 24.04.1 LTS", Supported: true}},
		Profiles: []engine.ProfileInfo{{ID: "kisa-2026", Revision: 1, Digest: digest}},
		Summary: map[string]engine.ProfileSummary{"kisa-2026": {
			Controls: map[engine.Status]int{engine.StatusFail: 1, engine.StatusError: 1, engine.StatusManual: 1, engine.StatusPass: 1, engine.StatusNotApplicable: 1},
		}},
		Controls: []engine.ControlResult{
			{Profile: "kisa-2026", ID: "U-01", Title: "Restrict direct remote root login", Severity: engine.SeverityHigh, Status: engine.StatusFail, Checks: []string{"ssh.permit-root-login"}},
			{Profile: "kisa-2026", ID: "U-02", Title: "Password policy", Severity: engine.SeverityHigh, Status: engine.StatusPass, Checks: []string{"accounts.password-max-age#3f9a1c2e"}},
			{Profile: "kisa-2026", ID: "U-04", Title: "Protect password hashes", Severity: engine.SeverityHigh, Status: engine.StatusError, Reason: "accounts.shadow-file: shadow: permission denied (run hostlint as root)", Checks: []string{"accounts.shadow-file"}},
			{Profile: "kisa-2026", ID: "U-06", Title: "Restrict su to a group", Severity: engine.SeverityHigh, Status: engine.StatusNotApplicable, Reason: "accounts.su-wheel-only: applies is false", Checks: []string{"accounts.su-wheel-only"}},
			{Profile: "kisa-2026", ID: "U-07", Title: "Remove unneeded accounts", Severity: engine.SeverityLow, Status: engine.StatusManual, Reason: "Review the listed accounts.", Checks: []string{"accounts.review-login-accounts"}},
		},
		Checks: []engine.CheckResult{
			{Ref: "accounts.password-max-age#3f9a1c2e", ID: "accounts.password-max-age", Version: 1, Digest: digest, Title: "Passwords expire", Severity: engine.SeverityMedium,
				Status: engine.StatusPass, StatusSource: "observed", Params: map[string]any{"max_days": 60},
				Evidence: []engine.Evidence{ev("login_defs.settings.PASS_MAX_DAYS", `"60" (explicit); expected 1–60`, "/etc/login.defs:165")}},
			{Ref: "accounts.review-login-accounts", ID: "accounts.review-login-accounts", Version: 1, Digest: digest, Title: "Review accounts that can log in", Severity: engine.SeverityLow,
				Status: engine.StatusManual, StatusSource: "observed", Reason: "Review the listed accounts.",
				Evidence: []engine.Evidence{ev("show[0]", "root (uid 0, /bin/bash)", ""), ev("show[1]", "alice (uid 1000, /bin/bash)", "")}},
			{Ref: "accounts.shadow-file", ID: "accounts.shadow-file", Version: 1, Digest: digest, Title: "Password hashes are kept in /etc/shadow", Severity: engine.SeverityHigh,
				Status: engine.StatusError, StatusSource: "observed", Reason: "shadow: permission denied (run hostlint as root)", Evidence: []engine.Evidence{}},
			{Ref: "accounts.su-wheel-only", ID: "accounts.su-wheel-only", Version: 1, Digest: digest, Title: "Only members of the wheel group can use su", Severity: engine.SeverityHigh,
				Status: engine.StatusNotApplicable, StatusSource: "observed", Reason: "applies is false", Evidence: []engine.Evidence{}},
			{Ref: "ssh.permit-root-login", ID: "ssh.permit-root-login", Version: 1, Digest: digest, Title: "SSH does not allow direct root login", Severity: engine.SeverityHigh,
				Status: engine.StatusFail, StatusSource: "observed",
				Evidence: []engine.Evidence{ev("sshd.config.permitrootlogin", `"yes" (explicit); expected one of [no]`, "/etc/ssh/sshd_config:32")}},
		},
		Collectors: []engine.CollectorRun{{Name: "sshd", Version: 1, Access: engine.AccessFilesystem, Status: "ok", Complete: true}},
	}
}

func TestGolden(t *testing.T) {
	tests := []struct {
		name, format string
		opts         Options
	}{
		{"table.golden", "table", Options{}},
		{"table-verbose.golden", "table", Options{Verbose: true}},
		{"table-color.golden", "table", Options{Color: true}},
		{"result.json.golden", "json", Options{}},
		{"result.sarif.golden", "sarif", Options{}},
		{"result.junit.golden", "junit", Options{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := Write(&buf, sampleResult(), tt.format, tt.opts); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join("testdata", tt.name)
			if *update {
				if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("%v (run go test ./internal/output -update)", err)
			}
			if !bytes.Equal(buf.Bytes(), want) {
				t.Errorf("%s differs from the golden file; run go test ./internal/output -update and review the diff\n%s", tt.name, buf.String())
			}
		})
	}
}

func TestJSONMatchesSchema(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, sampleResult(), "json", Options{}); err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	sch, err := c.Compile("../../schema/result-v1.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := jsonschema.UnmarshalJSON(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if err := sch.Validate(doc); err != nil {
		t.Error(err)
	}
}

func TestSARIFAndJUnitAreWellFormed(t *testing.T) {
	var sarif bytes.Buffer
	if err := Write(&sarif, sampleResult(), "sarif", Options{}); err != nil {
		t.Fatal(err)
	}
	var log sarifLog
	if err := json.Unmarshal(sarif.Bytes(), &log); err != nil {
		t.Fatal(err)
	}
	results := log.Runs[0].Results
	// One FAIL (error level, located at the sshd_config line) and one ERROR.
	if len(results) != 2 || results[1].Level != "error" || results[1].Locations[0].PhysicalLocation.Region.StartLine != 32 {
		t.Errorf("sarif results = %+v", results)
	}

	var junit bytes.Buffer
	if err := Write(&junit, sampleResult(), "junit", Options{}); err != nil {
		t.Fatal(err)
	}
	var suites junitSuites
	if err := xml.Unmarshal(junit.Bytes(), &suites); err != nil {
		t.Fatal(err)
	}
	s := suites.Suites[0]
	if s.Tests != 5 || s.Failures != 1 || s.Errors != 1 || s.Skipped != 2 {
		t.Errorf("junit suite = %+v", s)
	}
}

func TestUnknownFormat(t *testing.T) {
	if err := Write(&bytes.Buffer{}, sampleResult(), "yaml", Options{}); err == nil {
		t.Error("unknown format accepted")
	}
}

func TestWriteFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	if err := WriteFile(path, sampleResult(), "json", Options{}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || !json.Valid(data) {
		t.Errorf("report file: %v, valid JSON %v", err, json.Valid(data))
	}
}

// Text from the host cannot drive the terminal.
func TestTableEscapesHostText(t *testing.T) {
	tests := []struct{ in, want string }{
		{"  a\tb\n c ", "a b c"},
		{"evil\x1b[2J", `evil\x1b[2J`},
		{"file\u202egpj.exe", `file\u202egpj.exe`},
		{"계정 이름", "계정 이름"},
		{"bad\xffbyte", "bad\ufffdbyte"},
	}
	for _, tt := range tests {
		if got := oneLine(tt.in); got != tt.want {
			t.Errorf("oneLine(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// A failed render leaves an earlier report alone, and a link at the path is
// replaced instead of followed.
func TestWriteFileIsAtomicAndDoesNotFollowLinks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")
	if err := os.WriteFile(path, []byte("earlier report"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(path, sampleResult(), "yaml", Options{}); err == nil {
		t.Fatal("unknown format accepted")
	}
	if data, _ := os.ReadFile(path); string(data) != "earlier report" {
		t.Errorf("report after a failed render = %q", data)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("files left in the directory: %v", entries)
	}

	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(link, sampleResult(), "json", Options{}); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(victim); string(data) != "keep" {
		t.Errorf("the link's target was written: %q", data)
	}
	if fi, err := os.Lstat(link); err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o644 {
		t.Errorf("report: %v, %v", fi, err)
	}
}

// File paths in SARIF locations are valid URIs.
func TestSARIFLocationEscapesPaths(t *testing.T) {
	locs := sarifLocations([]engine.Evidence{{Source: "/etc/sudoers.d/my file#1:3"}, {Source: "/etc/ssh/sshd_config"}, {Source: "not a path"}})
	if len(locs) != 2 {
		t.Fatalf("locations = %+v", locs)
	}
	if got := locs[0].PhysicalLocation.ArtifactLocation.URI; got != "file:///etc/sudoers.d/my%20file%231" {
		t.Errorf("uri = %q", got)
	}
	if r := locs[0].PhysicalLocation.Region; r == nil || r.StartLine != 3 {
		t.Errorf("region = %+v", r)
	}
	if got := locs[1].PhysicalLocation.ArtifactLocation.URI; got != "file:///etc/ssh/sshd_config" || locs[1].PhysicalLocation.Region != nil {
		t.Errorf("uri = %q, region %+v", got, locs[1].PhysicalLocation.Region)
	}
}

// Evidence the engine capped is announced even when few items were kept.
func TestTableNotesOmittedEvidence(t *testing.T) {
	res := sampleResult()
	for i := range res.Checks {
		if res.Checks[i].Status == engine.StatusFail {
			res.Checks[i].Evidence = res.Checks[i].Evidence[:min(1, len(res.Checks[i].Evidence))]
			res.Checks[i].EvidenceOmitted = 40
		}
	}
	var b bytes.Buffer
	if err := Write(&b, res, "table", Options{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "… and 40 more") && !strings.Contains(b.String(), "… and 41 more") {
		t.Errorf("no note about omitted evidence:\n%s", b.String())
	}
}

// An attestation that did not apply is listed, like a waiver, so it is not
// silently ignored.
func TestTableListsAttestationsThatDidNotApply(t *testing.T) {
	res := sampleResult()
	res.Attestations = []engine.AttestationNote{{Check: "accounts.review-login-accounts", By: "alice", Expires: "2027-01-31",
		Problem: "stale: the observed value changed"}}
	var b bytes.Buffer
	if err := Write(&b, res, "table", Options{}); err != nil {
		t.Fatal(err)
	}
	want := "attestation of accounts.review-login-accounts by alice (until 2027-01-31) not applied: stale: the observed value changed"
	if !strings.Contains(b.String(), want) {
		t.Errorf("no line %q in:\n%s", want, b.String())
	}
}
