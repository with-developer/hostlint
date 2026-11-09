package output

import (
	"bytes"
	"regexp"
	"strings"
	"testing"

	"github.com/with-developer/vmsctl/internal/engine"
)

func TestMarkdownReport(t *testing.T) {
	res := readFixture(t, "web-01.json")
	var buf bytes.Buffer
	if err := Write(&buf, res, "markdown", Options{}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"## vmsctl: web-01", "| Profile | Controls |", "### Controls that need attention", "<details>", "</details>", "```"} {
		if !strings.Contains(out, want) {
			t.Errorf("the report lacks %q:\n%s", want, out)
		}
	}
	// Everything passes: one line says so.
	for i := range res.Controls {
		res.Controls[i].Status = engine.StatusPass
	}
	buf.Reset()
	if err := Write(&buf, res, "markdown", Options{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "Nothing failed") || strings.Contains(buf.String(), "<details>") {
		t.Errorf("a clean result:\n%s", buf.String())
	}
}

// What a scan shows comes from the scanned host or from a pack: it must not become a link, an image, HTML, a
// mention, an issue reference or math in the page that renders the Markdown.
func TestMarkdownIsInertForHostileText(t *testing.T) {
	payloads := []string{
		`<img src=x onerror=alert(1)>`, `[click](javascript:alert(1))`, `![i](http://evil.example/p.png)`,
		`@octocat please look, see #123`, `http://evil.example/ www.evil.example wWw.evil.example WWW.X.example mail me@evil.example`,
		`$$x$$`, "```", "````", "```\n</details><script>x</script>", "| a | b |", "\x1b[2J", "- [ ] list", "1. item", "12. item", "# heading", "> quote",
		"=== underline", "___", "<details><summary>x</summary>",
	}
	for _, payload := range payloads {
		res := readFixture(t, "web-01.json")
		res.Host.Hostname = payload
		res.Host.OS.Name = payload
		res.Scan.Packs = []engine.PackInfo{{Name: payload, Version: payload, Digest: payload}}
		res.Controls[0].Title = payload
		res.Controls[0].Status = engine.StatusFail
		for i := range res.Checks {
			res.Checks[i].Title = payload
			res.Checks[i].Status = engine.StatusFail
			res.Checks[i].Reason = payload
			res.Checks[i].Remediation = payload
			res.Checks[i].Evidence = []engine.Evidence{{Text: payload, Source: payload}, {Text: "a ``` b"}}
		}
		var buf bytes.Buffer
		if err := Write(&buf, res, "markdown", Options{}); err != nil {
			t.Fatal(err)
		}
		checkInert(t, payload, buf.String())
	}
}

// checkInert looks at the Markdown outside the code blocks, which is where text could be live, and at the
// code blocks, which only a longer run of backticks could end.
func checkInert(t *testing.T, payload, out string) {
	t.Helper()
	own := regexp.MustCompile(`</?(details|summary)>`)
	var prose []string
	var fence string
	for _, l := range strings.Split(own.ReplaceAllString(out, ""), "\n") {
		trimmed := strings.TrimLeft(l, "`")
		if run := len(l) - len(trimmed); run >= 3 && strings.TrimSpace(trimmed) == "" {
			switch {
			case fence == "":
				fence = l
			case run >= len(fence): // a closing fence is at least as long as the opening one
				if l != fence {
					t.Errorf("%q: a fence of %d backticks closes one of %d", payload, run, len(fence))
				}
				fence = ""
			}
			continue
		}
		if fence == "" {
			prose = append(prose, l)
		}
	}
	if fence != "" {
		t.Errorf("%q: a code block that is never closed", payload)
	}
	text := strings.Join(prose, "\n")
	for _, bad := range []string{"<img", "<script", "](", "javascript:", "http://", "https://", "@octocat", "#123", "www.", "WWW.", "wWw.", "$$", "me@evil", "\x1b"} {
		if strings.Contains(strings.ToLower(text), strings.ToLower(bad)) {
			t.Errorf("%q: %q is live in the report:\n%s", payload, bad, text)
		}
	}
	if strings.Contains(text, "<") {
		t.Errorf("%q: a raw < outside the report's own tags:\n%s", payload, text)
	}
	for _, l := range prose {
		trimmed := strings.TrimSpace(l)
		// No line the payload wrote starts a list, a heading, a quote or an ordered list.
		if strings.HasPrefix(l, "## vmsctl: ") || strings.HasPrefix(l, "### ") {
			continue // the report's own headings
		}
		if strings.Contains(l, "evil") || strings.Contains(l, "item") || strings.Contains(l, "list") || strings.Contains(l, "heading") || strings.Contains(l, "quote") || strings.Contains(l, "underline") {
			if regexp.MustCompile(`^(#|>|[-+=*_]{3,}|[-+*] |[0-9]+[.)] )`).MatchString(trimmed) {
				t.Errorf("%q: a line that starts Markdown structure: %q", payload, l)
			}
		}
		if strings.HasPrefix(l, "| ") && !strings.HasSuffix(strings.TrimSpace(l), "|") {
			t.Errorf("%q: a table row that is cut: %q", payload, l)
		}
	}
}

func TestMarkdownIsBounded(t *testing.T) {
	res := readFixture(t, "web-01.json")
	long := strings.Repeat("x", 100_000)
	res.Controls[0].Title = long
	res.Controls[0].Status = engine.StatusFail
	big := res.Checks[0]
	res.Checks = nil
	for i := range 3000 {
		c := big
		c.Ref = c.Ref + "-" + strings.Repeat("a", i%7) + string(rune('A'+i%26)) + strings.Repeat("b", i/26)
		c.Status = engine.StatusFail
		c.Evidence = []engine.Evidence{{Text: long}}
		res.Checks = append(res.Checks, c)
		res.Controls[0].Checks = append(res.Controls[0].Checks, c.Ref)
	}
	var buf bytes.Buffer
	if err := Write(&buf, res, "markdown", Options{}); err != nil {
		t.Fatal(err)
	}
	if buf.Len() > 900<<10 {
		t.Errorf("the report is %d KiB; a job summary takes 1 MiB", buf.Len()>>10)
	}
	if strings.Contains(buf.String(), long) {
		t.Error("a line of 100000 characters was not cut")
	}
}

func TestMarkdownExplainsAControlWhoseChecksAreHidden(t *testing.T) {
	res := readFixture(t, "web-01.json")
	res.Controls[0].Status = engine.StatusError
	res.Controls[0].Reason = "the file could not be read"
	for i := range res.Checks {
		res.Checks[i].Status = engine.StatusPass
	}
	var buf bytes.Buffer
	if err := Write(&buf, res, "markdown", Options{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "the file could not be read") {
		t.Errorf("the reason of the control is not there:\n%s", buf.String())
	}
}

func TestMarkdownDetailsNameTheProfileOfSeveral(t *testing.T) {
	res := readFixture(t, "web-01.json")
	res.Profiles = append(res.Profiles, engine.ProfileInfo{ID: "x-other", Revision: 1, Digest: "sha256:" + strings.Repeat("a", 64)})
	res.Summary["x-other"] = engine.ProfileSummary{Controls: map[engine.Status]int{engine.StatusFail: 1}}
	res.Controls = append(res.Controls, engine.ControlResult{Profile: "x-other", ID: res.Controls[0].ID, Title: "same ID", Status: engine.StatusFail, Severity: engine.SeverityLow, Checks: []string{}})
	var buf bytes.Buffer
	if err := Write(&buf, res, "markdown", Options{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "<summary>x&#45;other") && !strings.Contains(buf.String(), "<summary>x-other") {
		t.Errorf("the profile is not in the summary:\n%s", buf.String())
	}
}

func TestMarkdownIsAFormat(t *testing.T) {
	if !ValidFormat("markdown") {
		t.Error("markdown is not a format")
	}
}

// A failed check shows how to fix it, in the same inert text as the rest, cut at a bound.
func TestMarkdownShowsTheFixHint(t *testing.T) {
	res := readFixture(t, "web-01.json")
	hinted := ""
	for i := range res.Checks {
		if res.Checks[i].Status == engine.StatusFail {
			res.Checks[i].Remediation = "Set `PermitRootLogin no` in sshd_config.\nThen reload sshd."
			hinted = res.Checks[i].ID
			break
		}
	}
	if hinted == "" {
		t.Fatal("the fixture has no failing check: the test needs one")
	}
	var buf bytes.Buffer
	if err := Write(&buf, res, "markdown", Options{}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "**How to fix:** Set &#96;PermitRootLogin no&#96; in sshd&#95;config. Then reload sshd.") {
		t.Errorf("no fix hint, or not escaped:\n%s", out)
	}
	if strings.Count(out, "How to fix") != 1 {
		t.Errorf("%d hints, want 1", strings.Count(out, "How to fix"))
	}
	// Checks of one control that share a hint show it once.
	dup := readFixture(t, "web-01.json")
	var first *engine.CheckResult
	for i := range dup.Checks {
		if dup.Checks[i].Status == engine.StatusFail {
			first = &dup.Checks[i]
			break
		}
	}
	second := *first
	second.Ref, second.ID = "x.second-check", "x.second-check"
	first.Remediation, second.Remediation = "Same hint.", "Same hint."
	dup.Checks = append(dup.Checks, second)
	for i := range dup.Controls {
		for _, ref := range dup.Controls[i].Checks {
			if ref == first.Ref {
				dup.Controls[i].Checks = append(dup.Controls[i].Checks, second.Ref)
			}
		}
	}
	buf.Reset()
	if err := Write(&buf, dup, "markdown", Options{}); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(buf.String(), "Same hint."); n != 1 || !strings.Contains(buf.String(), "x&#46;second") && !strings.Contains(buf.String(), "x.second-check") {
		t.Errorf("a hint shared by two failing checks of a control is shown %d times (second check listed: %v)", n, strings.Contains(buf.String(), "second-check"))
	}
	// A hint longer than the bound is cut.
	for i := range res.Checks {
		if res.Checks[i].Remediation != "" {
			res.Checks[i].Remediation = strings.Repeat("x", 5*maxMarkdownFix)
		}
	}
	buf.Reset()
	if err := Write(&buf, res, "markdown", Options{}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), strings.Repeat("x", maxMarkdownFix+1)) {
		t.Error("a hint over the bound is not cut")
	}
}
