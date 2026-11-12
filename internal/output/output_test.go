package output

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall" //nolint:depguard // the test makes a FIFO
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/with-developer/vmsctl/internal/engine"
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
			Tool: engine.ToolInfo{Name: "vmsctl", Version: "v0.1.0"}, Target: engine.TargetInfo{Kind: "host", Root: "/"},
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
			{Profile: "kisa-2026", ID: "U-04", Title: "Protect password hashes", Severity: engine.SeverityHigh, Status: engine.StatusError, Reason: "accounts.shadow-file: shadow: permission denied (run vmsctl as root)", Checks: []string{"accounts.shadow-file"}},
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
				Status: engine.StatusError, StatusSource: "observed", Reason: "shadow: permission denied (run vmsctl as root)", Evidence: []engine.Evidence{}},
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

// A check whose controls are all waived is a suppressed result; one with an unwaived control is not.
func TestSARIFSuppressesControlWaivedChecks(t *testing.T) {
	res := sampleResult()
	res.Controls[0].Status = engine.StatusWaived
	res.Controls[0].Waiver = &engine.WaiverOf{Reason: "accepted until the migration", Scope: "control"}
	var buf bytes.Buffer
	if err := Write(&buf, res, "sarif", Options{}); err != nil {
		t.Fatal(err)
	}
	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatal(err)
	}
	for _, r := range log.Runs[0].Results {
		if r.RuleID == "ssh.permit-root-login" {
			if len(r.Suppressions) != 1 || r.Suppressions[0].Kind != "external" || r.Suppressions[0].Justification != "accepted until the migration" {
				t.Errorf("suppressions = %+v", r.Suppressions)
			}
		} else if len(r.Suppressions) != 0 {
			t.Errorf("%s is suppressed", r.RuleID)
		}
	}
	// A check that another, unwaived control also holds stays active.
	res.Controls = append(res.Controls, engine.ControlResult{Profile: "other", ID: "X-1", Status: engine.StatusFail, Checks: []string{"ssh.permit-root-login"}})
	if _, ok := waivedByControls(res)["ssh.permit-root-login"]; ok {
		t.Error("a check held by an unwaived control is suppressed")
	}
}

// The controls property is an empty list, not null, and locations stop at the cap.
func TestSARIFControlsAreNeverNullAndLocationsAreCapped(t *testing.T) {
	res := sampleResult()
	res.Controls = nil
	var buf bytes.Buffer
	if err := Write(&buf, res, "sarif", Options{}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), `"controls": null`) || strings.Contains(buf.String(), `"controls":null`) {
		t.Error("controls is null")
	}
	var ev []engine.Evidence
	for i := 0; i < 25; i++ {
		ev = append(ev, engine.Evidence{Source: "/etc/f" + strings.Repeat("x", i) + ":1"})
	}
	if got := len(sarifLocations(ev)); got != maxSarifLocations {
		t.Errorf("locations = %d, want %d", got, maxSarifLocations)
	}
}

// The status column keeps its width when color is on.
func TestTableAlignsStatusWithColor(t *testing.T) {
	plain, colored := strings.Builder{}, strings.Builder{}
	if err := Write(&plain, sampleResult(), "table", Options{}); err != nil {
		t.Fatal(err)
	}
	if err := Write(&colored, sampleResult(), "table", Options{Color: true}); err != nil {
		t.Fatal(err)
	}
	strip := regexp.MustCompile("\x1b\\[[0-9;]*m")
	if got := strip.ReplaceAllString(colored.String(), ""); got != plain.String() {
		t.Errorf("colored output differs from plain once the escapes are removed:\n%s\nvs\n%s", got, plain.String())
	}
}

// --output /dev/null (or any stream) writes to the device instead of replacing it, and a
// device or pipe that is not a stream is refused.
func TestWriteFileStreamsAndDevices(t *testing.T) {
	if err := WriteFile("/dev/null", sampleResult(), "json", Options{}); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Lstat("/dev/null"); err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		t.Fatalf("/dev/null is now %v, %v", fi, err)
	}
	fifo := filepath.Join(t.TempDir(), "out")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("no FIFOs here: %v", err)
	}
	if err := WriteFile(fifo, sampleResult(), "json", Options{}); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("err = %v", err)
	}
	if fi, err := os.Lstat(fifo); err != nil || fi.Mode()&os.ModeNamedPipe == 0 {
		t.Errorf("the FIFO was replaced: %v, %v", fi, err)
	}
}

// /dev/fd/N that is a regular file is refused, and a path with ".." is not a stream.
func TestWriteFileRefusesFileBehindFD(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "log")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString("earlier log line\n"); err != nil {
		t.Fatal(err)
	}
	fd := "/dev/fd/" + strconv.Itoa(int(f.Fd()))
	if _, statErr := os.Stat(fd); statErr != nil {
		t.Skipf("no /dev/fd here: %v", statErr)
	}
	if err := WriteFile(fd, sampleResult(), "json", Options{}); err == nil || !strings.Contains(err.Error(), "not a stream") {
		t.Errorf("err = %v", err)
	}
	if data, _ := os.ReadFile(f.Name()); string(data) != "earlier log line\n" {
		t.Errorf("the file was written: %q", data)
	}
	if isStream(fd + "/../x") {
		t.Error("a path with .. is a stream")
	}
}

// An existing report keeps its mode; a new one is 0644.
func TestWriteFileKeepsMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(path, sampleResult(), "json", Options{}); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v, want 0600", fi.Mode().Perm())
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

// A control that has no checks shows its guidance: without it the table would
// say MANUAL and not what to look at.
func TestTableShowsGuidanceOfControlsWithoutChecks(t *testing.T) {
	res := sampleResult()
	res.Controls = append(res.Controls, engine.ControlResult{
		Profile: res.Profiles[0].ID, ID: "U-62", Title: "Login banners warn against misuse", Severity: engine.SeverityLow,
		Status: engine.StatusManual, Reason: "Check the banners\nin /etc/issue.", Checks: []string{},
	})
	var b bytes.Buffer
	if err := Write(&b, res, "table", Options{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "Login banners warn against misuse [low]\n    Check the banners in /etc/issue.\n") {
		t.Errorf("no guidance under U-62:\n%s", b.String())
	}
}

// A check that does not apply says nothing about why its control fails: the
// table leaves it out unless --verbose asks for everything.
func TestTableHidesNotApplicableChecksUnlessVerbose(t *testing.T) {
	res := sampleResult()
	var na string
	for _, c := range res.Checks {
		if c.Status == engine.StatusNotApplicable {
			na = c.ID
		}
	}
	if na == "" {
		t.Skip("the sample has no NOT_APPLICABLE check")
	}
	for _, verbose := range []bool{false, true} {
		var b bytes.Buffer
		if err := Write(&b, res, "table", Options{Verbose: verbose}); err != nil {
			t.Fatal(err)
		}
		// Only a control that is shown can show its checks: look for the check line.
		if got := strings.Contains(b.String(), "- "+na); got != verbose {
			t.Errorf("verbose %v: %s listed = %v\n%s", verbose, na, got, b.String())
		}
	}
}

// A mounted image often has no host name: the header says so instead of
// leaving a gap.
func TestTableHeaderWithoutHostName(t *testing.T) {
	res := sampleResult()
	res.Host.Hostname = ""
	var b bytes.Buffer
	if err := Write(&b, res, "table", Options{}); err != nil {
		t.Fatal(err)
	}
	if first, _, _ := strings.Cut(b.String(), "\n"); !strings.Contains(first, "(no host name)") || strings.Contains(first, "·  ") {
		t.Errorf("header %q", first)
	}
}

// The fix hint of a failed check reaches SARIF as the rule's help, which code scanning shows with the alert.
func TestSARIFCarriesTheFixHintAsHelp(t *testing.T) {
	res := sampleResult()
	for i := range res.Checks {
		if res.Checks[i].Status == engine.StatusFail {
			res.Checks[i].Remediation = "Set `PermitRootLogin no`."
		}
	}
	var buf bytes.Buffer
	if err := Write(&buf, res, "sarif", Options{}); err != nil {
		t.Fatal(err)
	}
	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatal(err)
	}
	withHelp := 0
	for _, r := range log.Runs[0].Tool.Driver.Rules {
		if r.Help != nil {
			withHelp++
			if r.ID != "ssh.permit-root-login" || r.Help.Text != "Set `PermitRootLogin no`." {
				t.Errorf("help on %s: %+v", r.ID, r.Help)
			}
		}
	}
	if withHelp != 1 {
		t.Errorf("%d rules have help, want 1", withHelp)
	}
}

// The titles of controls and checks come in Korean where there is one and where it is asked for, in the table and in Markdown;
// without a Korean title, or without the language, they are English, and the machine formats are never translated.
func TestKoreanTitles(t *testing.T) {
	res := readFixture(t, "web-01.json")
	for i := range res.Controls {
		res.Controls[i].TitleKo = "한글" + res.Controls[i].ID
		res.Controls[i].Status = engine.StatusFail
	}
	for i := range res.Checks {
		res.Checks[i].TitleKo = "점검" + res.Checks[i].ID
		res.Checks[i].Status = engine.StatusFail
	}
	res.Controls[0].TitleKo = "" // a control without a Korean title stays English
	for _, format := range []string{"table", "markdown"} {
		var en, ko bytes.Buffer
		if err := Write(&en, res, format, Options{Verbose: true}); err != nil {
			t.Fatal(err)
		}
		if err := Write(&ko, res, format, Options{Verbose: true, Lang: "ko"}); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(en.String(), "한글") || strings.Contains(en.String(), "점검") {
			t.Errorf("%s: Korean without being asked for", format)
		}
		if !strings.Contains(ko.String(), "한글"+res.Controls[1].ID) || !strings.Contains(ko.String(), "점검"+res.Checks[0].ID) {
			t.Errorf("%s: no Korean titles:\n%s", format, ko.String())
		}
		if !strings.Contains(ko.String(), res.Controls[0].Title) {
			t.Errorf("%s: the control without a Korean title lost its English one", format)
		}
	}
	for _, format := range []string{"json", "sarif", "junit"} {
		var en, ko bytes.Buffer
		_ = Write(&en, res, format, Options{})
		_ = Write(&ko, res, format, Options{Lang: "ko"})
		if en.String() != ko.String() {
			t.Errorf("%s changes with --lang", format)
		}
	}
}

// The fix hint of the Markdown report is Korean on request where the check has one, and English otherwise; the CSV has both.
func TestKoreanFixHints(t *testing.T) {
	res := readFixture(t, "web-01.json")
	for i := range res.Checks {
		res.Checks[i].Status = engine.StatusFail
		res.Checks[i].Remediation = "Set it right (" + res.Checks[i].ID + ")."
	}
	res.Checks[0].RemediationKo = "올바르게 설정하세요."
	for i := range res.Controls {
		res.Controls[i].Status = engine.StatusFail
	}
	var en, ko, csvOut bytes.Buffer
	_ = Write(&en, res, "markdown", Options{})
	_ = Write(&ko, res, "markdown", Options{Lang: "ko"})
	_ = Write(&csvOut, res, "csv", Options{})
	if strings.Contains(en.String(), "올바르게") || !strings.Contains(en.String(), "**How to fix:**") {
		t.Errorf("English by default:\n%s", en.String())
	}
	if !strings.Contains(ko.String(), "**조치 방법:** 올바르게 설정하세요.") || !strings.Contains(ko.String(), "**How to fix:** Set it right") {
		t.Errorf("a check with Korean guidance, and one without:\n%s", ko.String())
	}
	if !strings.Contains(csvOut.String(), "올바르게 설정하세요.") {
		t.Error("the CSV has no Korean fix hint")
	}
}
