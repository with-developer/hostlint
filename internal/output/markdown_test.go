package output

import (
	"bytes"
	"regexp"
	"strings"
	"testing"

	"github.com/with-developer/hostlint/internal/engine"
)

func TestMarkdownReport(t *testing.T) {
	res := readFixture(t, "web-01.json")
	var buf bytes.Buffer
	if err := Write(&buf, res, "markdown", Options{}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"## hostlint: web-01", "| Profile | Controls |", "### Controls that need attention", "<details>", "</details>", "```"} {
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
	res := readFixture(t, "web-01.json")
	evil := []string{
		`<img src=x onerror=alert(1)>`, `[click](javascript:alert(1))`, `![i](http://evil.example/p.png)`,
		`@octocat please look, see #123`, `http://evil.example/ www.evil.example mail me@evil.example`, `$$x$$`,
		"```\n</details><script>x</script>", "| a | b |", "\x1b[2J", "- [ ] list",
	}
	res.Host.Hostname = evil[0] + evil[3]
	res.Host.OS.Name = evil[1]
	res.Scan.Packs = []engine.PackInfo{{Name: evil[2], Version: evil[3], Digest: evil[4]}}
	res.Controls[0].Title = evil[5]
	res.Controls[0].Status = engine.StatusFail
	for i := range res.Checks {
		res.Checks[i].Title = evil[6]
		res.Checks[i].Status = engine.StatusFail
		res.Checks[i].Reason = evil[7]
		res.Checks[i].Evidence = nil
		for _, e := range append([]string{"a ``` b"}, evil...) {
			res.Checks[i].Evidence = append(res.Checks[i].Evidence, engine.Evidence{Text: e, Source: evil[1]})
		}
	}
	var buf bytes.Buffer
	if err := Write(&buf, res, "markdown", Options{}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	// Take away what the report itself writes, and look at what is left.
	own := regexp.MustCompile(`</?(details|summary)>`)
	outside := own.ReplaceAllString(out, "")
	// Inside a code block only characters that end it matter; outside, nothing may be live.
	var prose []string
	inFence := false
	for _, l := range strings.Split(outside, "\n") {
		if strings.HasPrefix(l, "```") {
			inFence = !inFence
			continue
		}
		if !inFence {
			prose = append(prose, l)
		}
	}
	text := strings.Join(prose, "\n")
	for _, bad := range []string{"<img", "<script", "](", "javascript:", "http://", "https://", "@octocat", "#123", "www.evil", "$$", "me@evil", "\x1b"} {
		if strings.Contains(text, bad) {
			t.Errorf("%q is live in the report:\n%s", bad, text)
		}
	}
	if strings.Contains(text, "<") {
		t.Errorf("a raw < outside the report's own tags:\n%s", text)
	}
	// A table row keeps its cells: no pipe of the host's text is raw.
	for _, l := range prose {
		if strings.HasPrefix(l, "| ") && strings.Count(l, "|") != strings.Count(strings.TrimSpace(l), "|") {
			t.Errorf("row %q", l)
		}
	}
	// The block that holds the evidence is fenced with more backticks than the evidence has in a row.
	if !strings.Contains(out, "````\n") {
		t.Errorf("a longer fence was not used:\n%s", out)
	}
}

func TestMarkdownIsAFormat(t *testing.T) {
	if !ValidFormat("markdown") {
		t.Error("markdown is not a format")
	}
}
