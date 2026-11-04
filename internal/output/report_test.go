package output

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// The fixtures: web-01, an older scan of web-01 that the report leaves out,
// and db-01 (not root, a newer profile revision with another control, waived
// results, a waiver that did not apply, a failed collector, and evidence that
// tries to break out of the page's data element).
var reportFixtures = []string{"web-01.json", "db-01.json", "web-01-old.json"}

var reportOpts = ReportOptions{Tool: "v0.1.0", Now: time.Date(2026, 11, 3, 9, 0, 0, 0, time.UTC)}

func reportInputs(t *testing.T) []ReportInput {
	t.Helper()
	var inputs []ReportInput
	for _, name := range reportFixtures {
		f, err := os.Open(filepath.Join("testdata", "report", name))
		if err != nil {
			t.Fatal(err)
		}
		res, err := ReadResult(f)
		_ = f.Close()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		inputs = append(inputs, ReportInput{Name: name, Result: res})
	}
	return inputs
}

func TestReportFixturesMatchSchema(t *testing.T) {
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	sch, err := c.Compile("../../schema/result-v1.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range reportFixtures {
		f, err := os.Open(filepath.Join("testdata", "report", name))
		if err != nil {
			t.Fatal(err)
		}
		doc, err := jsonschema.UnmarshalJSON(f)
		_ = f.Close()
		if err != nil {
			t.Fatal(err)
		}
		if err := sch.Validate(doc); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestReportData(t *testing.T) {
	data, err := buildReport(reportInputs(t), reportOpts)
	if err != nil {
		t.Fatal(err)
	}
	got, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	golden := filepath.Join("testdata", "report", "data.golden.json")
	if *update {
		if err := os.WriteFile(golden, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("%v (run go test ./internal/output -update)", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("report data differs from %s; run go test ./internal/output -update and review the diff\n%s", golden, got)
	}
}

func TestReportPage(t *testing.T) {
	opts := reportOpts
	opts.Title = `Q4 <b>audit</b>`
	var buf bytes.Buffer
	if err := WriteReport(&buf, reportInputs(t), opts); err != nil {
		t.Fatal(err)
	}
	page := buf.String()

	if n := strings.Count(page, "</script"); n != 2 {
		t.Errorf("%d </script in the page; want 2, the data and the code", n)
	}
	for _, bad := range []string{"<script>alert", "<!--", "<b>audit"} {
		if strings.Contains(page, bad) {
			t.Errorf("%q reached the page unescaped", bad)
		}
	}
	if !strings.Contains(page, "<title>Q4 &lt;b&gt;audit&lt;/b&gt;</title>") {
		t.Error("title not escaped as text")
	}

	// The data element holds the report data, and nothing else.
	m := regexp.MustCompile(`(?s)<script id="report-data" type="application/json">(.*?)</script>`).FindStringSubmatch(page)
	if m == nil {
		t.Fatal("no data element")
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(m[1]), &got); err != nil {
		t.Fatal(err)
	}
	data, err := buildReport(reportInputs(t), opts)
	if err != nil {
		t.Fatal(err)
	}
	wantJSON, _ := json.Marshal(data)
	var want map[string]any
	_ = json.Unmarshal(wantJSON, &want)
	gotJSON, _ := json.Marshal(got)
	if !bytes.Equal(gotJSON, mustJSON(t, want)) {
		t.Error("the embedded data differs from the report data")
	}
	// Every < and > is escaped, and so are the JavaScript line terminators
	// U+2028 and U+2029, yet the hostile evidence arrives intact.
	if strings.ContainsAny(m[1], "<>\xe2\x80\xa8\xe2\x80\xa9") {
		t.Error("the embedded data has an unescaped <, > or line terminator")
	}
	hostile := "x</script><script>alert(1)</script><!-- & \"quoted\" \xe2\x80\xa8"
	if strs, _ := got["strings"].([]any); !slices.Contains(strs, any(hostile)) {
		t.Error("the hostile evidence did not survive the round trip")
	}

	// The policy allows exactly the inline style and script of the page,
	// and no other source.
	style := regexp.MustCompile(`(?s)<style>(.*?)</style>`).FindStringSubmatch(page)
	script := regexp.MustCompile(`(?s)<script>(.*?)</script>`).FindStringSubmatch(page)
	csp := regexp.MustCompile(`<meta http-equiv="Content-Security-Policy" content="([^"]*)">`).FindStringSubmatch(page)
	if style == nil || script == nil || csp == nil {
		t.Fatal("style, script or policy missing")
	}
	wantCSP := "default-src 'none'; style-src '" + cspHash(style[1]) + "'; script-src '" + cspHash(script[1]) +
		"'; img-src data:; base-uri 'none'; form-action 'none'"
	if csp[1] != wantCSP {
		t.Errorf("policy %q\nwant   %q", csp[1], wantCSP)
	}
	if strings.Index(page, "Content-Security-Policy") > strings.Index(page, "<style>") {
		t.Error("the policy must come before the style and script it governs")
	}
	if regexp.MustCompile(`(?i)\b(src|href|action)\s*=\s*"(https?:)?//`).MatchString(page) {
		t.Error("the page refers to another site")
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestReadResultRejects(t *testing.T) {
	base, err := os.ReadFile(filepath.Join("testdata", "report", "web-01.json"))
	if err != nil {
		t.Fatal(err)
	}
	edit := func(f func(doc map[string]any)) string {
		var doc map[string]any
		if err := json.Unmarshal(base, &doc); err != nil {
			t.Fatal(err)
		}
		f(doc)
		return string(mustJSON(t, doc))
	}
	first := func(doc map[string]any, key string) map[string]any { return doc[key].([]any)[0].(map[string]any) }
	tests := []struct{ name, doc, want string }{
		{"not JSON", "<html>", "not a hostlint result"},
		{"no version", `{"scan": {}}`, "no schemaVersion"},
		{"newer version", `{"schemaVersion": 2}`, "schema version 2 is not supported"},
		{"no host name", edit(func(d map[string]any) { d["host"].(map[string]any)["hostname"] = "" }), "no host name"},
		{"unknown control status", edit(func(d map[string]any) { first(d, "controls")["status"] = "OK" }), `unknown status "OK"`},
		{"unknown check status", edit(func(d map[string]any) { first(d, "checks")["status"] = "<b>" }), "unknown status"},
		{"unknown original status", edit(func(d map[string]any) { first(d, "checks")["originalStatus"] = "MAYBE" }), "unknown original status"},
		{"unknown check", edit(func(d map[string]any) { first(d, "controls")["checks"] = []any{"nope"} }), `unknown check "nope"`},
		{"unknown profile", edit(func(d map[string]any) { first(d, "controls")["profile"] = "other" }), `unknown profile "other"`},
		{"control twice", edit(func(d map[string]any) {
			d["controls"] = append(d["controls"].([]any), first(d, "controls"))
		}), "listed twice"},
		{"scan time not a timestamp", edit(func(d map[string]any) { d["scan"].(map[string]any)["startedAt"] = "yesterday" }), "is not a timestamp"},
		{"severity that is a class list", edit(func(d map[string]any) { first(d, "checks")["severity"] = "high s-FAIL" }), "unknown severity"},
		{"control severity unknown", edit(func(d map[string]any) { first(d, "controls")["severity"] = "critical" }), "unknown severity"},
		{"wrong type", edit(func(d map[string]any) { d["checks"] = "all good" }), "not a valid hostlint result"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ReadResult(strings.NewReader(tt.doc)); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v; want %q", err, tt.want)
			}
		})
	}
}

func TestReportNeedsResults(t *testing.T) {
	if err := WriteReport(&bytes.Buffer{}, nil, reportOpts); err == nil {
		t.Error("a report without results was written")
	}
}

func TestNaturalCompare(t *testing.T) {
	ordered := []string{"", "db", "db-1", "db-01a", "web-2", "web-9", "web-10", "web-10a", "web-100", "web-a"}
	for i := range ordered {
		for j := range ordered {
			got := naturalCompare(ordered[i], ordered[j])
			if (i < j && got >= 0) || (i > j && got <= 0) || (i == j && got != 0) {
				t.Errorf("naturalCompare(%q, %q) = %d", ordered[i], ordered[j], got)
			}
		}
	}
}
