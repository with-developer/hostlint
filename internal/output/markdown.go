package output

import (
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/with-developer/vmsctl/internal/engine"
)

// Limits of the Markdown report: it is for a page a person reads (a job summary, a pull request comment),
// not for the whole result, which is the JSON.
const (
	maxMarkdownControls = 200
	maxMarkdownDetails  = 30
	maxMarkdownEvidence = 5
	maxMarkdownChecks   = 40
	// maxMarkdownBytes keeps the report under what a job summary takes (1 MiB) with room to spare: past it
	// the details stop, and the report says so.
	maxMarkdownBytes = 700 << 10
	// maxMarkdownLine is the longest text of one cell, line or evidence line; the rest is cut.
	maxMarkdownLine = 300
	// maxMarkdownFix is the longest fix hint of a check shown whole: what the engine keeps of one (1500 bytes), so
	// a hint is never cut in the middle of a step.
	maxMarkdownFix = 1500
)

var wwwRe = regexp.MustCompile(`(?i)(www)\.`)

// clip cuts text that is longer than a line of the report.
func clip(s string) string { return clipTo(s, maxMarkdownLine) }

func clipTo(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "..."
}

// mdText makes text safe for Markdown that GitHub, GitLab and others render: what a scan prints comes from
// the scanned host (a file name, a value in a configuration) or from a pack, and must not become a link, an
// image, HTML, a mention or an issue reference. Every character that means something is written as a
// character reference, which shows as the character and is nothing else; control characters and line
// breaks are escaped as in the table.
func mdText(s string) string { return mdTextTo(s, maxMarkdownLine) }

// mdTextTo is mdText with another limit for the length.
func mdTextTo(s string, n int) string {
	s = clipTo(oneLine(s), n)
	var b strings.Builder
	for i, r := range s {
		switch r {
		case '&', '<', '>', '@', '#', '|', '`', '*', '_', '[', ']', '(', ')', '!', '~', '\\', '$', ':':
			fmt.Fprintf(&b, "&#%d;", r)
		case '-', '+', '=':
			if i == 0 { // a line that starts with these is a list or a heading underline
				fmt.Fprintf(&b, "&#%d;", r)
			} else {
				b.WriteRune(r)
			}
		case '.':
			// "1. " at the start of a line is a list; "www." makes a link of what follows it.
			if orderedMarker(s[:i]) {
				b.WriteString("&#46;")
			} else {
				b.WriteRune(r)
			}
		default:
			b.WriteRune(r)
		}
	}
	return wwwRe.ReplaceAllString(b.String(), "${1}&#46;")
}

// orderedMarker reports whether before is only digits: a dot after it starts an ordered list.
func orderedMarker(before string) bool {
	return before != "" && strings.Trim(before, "0123456789") == ""
}

// mdFence puts lines in a code block whose fence is longer than any run of backticks in them.
func mdFence(lines []string) string {
	run, longest := 0, 0
	for _, l := range lines {
		run = 0
		for _, r := range l {
			if r == '`' {
				run++
				longest = max(longest, run)
			} else {
				run = 0
			}
		}
	}
	fence := strings.Repeat("`", max(3, longest+1))
	return fence + "\n" + strings.Join(lines, "\n") + "\n" + fence + "\n"
}

func writeMarkdown(w io.Writer, res *engine.Result, lang string) error {
	var b strings.Builder
	host := oneLine(res.Host.Hostname)
	if host == "" {
		host = "(no host name)"
	}
	fmt.Fprintf(&b, "## vmsctl: %s\n\n", mdText(host))
	var profiles []string
	for _, pr := range res.Profiles {
		profiles = append(profiles, mdText(pr.ID))
	}
	line := fmt.Sprintf("vmsctl %s &middot; %s", mdText(res.Scan.Tool.Version), strings.Join(profiles, ", "))
	if name := oneLine(res.Host.OS.Name); name != "" {
		line += " &middot; " + mdText(name)
	}
	fmt.Fprintf(&b, "%s\n\n", line)
	if res.Scan.Target.Kind == "root" {
		fmt.Fprintf(&b, "Scanned `%s`: live checks are not available.\n\n", strings.NewReplacer("`", "'").Replace(oneLine(res.Scan.Target.Root)))
	}
	for _, p := range res.Scan.Packs {
		fmt.Fprintf(&b, "Policy pack %s %s (%s).\n\n", mdText(p.Name), mdText(p.Version), mdText(p.Digest))
	}
	if res.Scan.Privileges.EUID != 0 && res.Scan.Target.Kind == "host" {
		b.WriteString("Not running as root: checks that need protected files report ERROR.\n\n")
	}

	// Summary: one row per profile.
	statuses := engine.Statuses()
	b.WriteString("| Profile | Controls |")
	sep := "|---|---:|"
	for _, st := range statuses {
		fmt.Fprintf(&b, " %s |", st)
		sep += "---:|"
	}
	b.WriteString("\n" + sep + "\n")
	for _, pr := range res.Profiles {
		s := res.Summary[pr.ID]
		total := 0
		for _, n := range s.Controls {
			total += n
		}
		fmt.Fprintf(&b, "| %s | %d |", mdText(pr.ID), total)
		for _, st := range statuses {
			fmt.Fprintf(&b, " %d |", s.Controls[st])
		}
		b.WriteString("\n")
	}
	b.WriteString("\n")

	needs := func(st engine.Status) bool {
		return st == engine.StatusFail || st == engine.StatusError || st == engine.StatusManual
	}
	var attention []engine.ControlResult
	for _, c := range res.Controls {
		if needs(c.Status) {
			attention = append(attention, c)
		}
	}
	if len(attention) == 0 {
		b.WriteString("Nothing failed, and nothing needs a person.\n")
		_, err := io.WriteString(w, b.String())
		return err
	}
	fmt.Fprintf(&b, "### Controls that need attention (%d)\n\n", len(attention))
	multi := len(res.Profiles) > 1
	if multi {
		b.WriteString("| Profile | Control | Severity | Status | Title |\n|---|---|---|---|---|\n")
	} else {
		b.WriteString("| Control | Severity | Status | Title |\n|---|---|---|---|\n")
	}
	for i, c := range attention {
		if i == maxMarkdownControls {
			fmt.Fprintf(&b, "\n%d more controls are not listed; the JSON result has them all.\n", len(attention)-i)
			break
		}
		if multi {
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n", mdText(c.Profile), mdText(c.ID), c.Severity, c.Status, mdText(titleIn(lang, c.Title, c.TitleKo)))
		} else {
			fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", mdText(c.ID), c.Severity, c.Status, mdText(titleIn(lang, c.Title, c.TitleKo)))
		}
	}

	checks := map[string]engine.CheckResult{}
	for _, c := range res.Checks {
		checks[c.Ref] = c
	}
	b.WriteString("\n### Details\n\n")
	for i, c := range attention {
		if i == maxMarkdownDetails || b.Len() > maxMarkdownBytes {
			fmt.Fprintf(&b, "%d more controls have no details here; the JSON result has everything.\n", len(attention)-i)
			break
		}
		name := mdText(c.ID)
		if multi {
			name = mdText(c.Profile) + " " + name
		}
		fmt.Fprintf(&b, "<details>\n<summary>%s %s &mdash; %s</summary>\n\n", name, c.Status, mdText(titleIn(lang, c.Title, c.TitleKo)))
		wrote := false
		if c.Reason != "" && (len(c.Checks) == 0 || c.Waiver != nil) {
			fmt.Fprintf(&b, "%s\n\n", mdText(c.Reason))
			wrote = true
		}
		listed := 0
		hinted := map[string]bool{} // checks of one control often share a hint: it is shown once
		for _, ref := range c.Checks {
			ck, ok := checks[ref]
			if !ok || ck.Status == engine.StatusPass || ck.Status == engine.StatusNotApplicable {
				continue
			}
			if listed++; listed > maxMarkdownChecks || b.Len() > maxMarkdownBytes {
				b.WriteString("More checks of this control are not listed here.\n\n")
				break
			}
			wrote = true
			fmt.Fprintf(&b, "**%s** %s &mdash; %s\n\n", mdText(ck.ID), ck.Status, mdText(titleIn(lang, ck.Title, ck.TitleKo)))
			if ck.Reason != "" && ck.Status != engine.StatusFail {
				fmt.Fprintf(&b, "%s\n\n", mdText(ck.Reason))
			}
			var ev []string
			for j, e := range ck.Evidence {
				if j == maxMarkdownEvidence {
					ev = append(ev, fmt.Sprintf("... and %d more", len(ck.Evidence)-j))
					break
				}
				text := clip(oneLine(e.Text))
				if src := clip(oneLine(e.Source)); src != "" && !strings.Contains(text, src) {
					text += "  [" + src + "]"
				}
				ev = append(ev, text)
			}
			if len(ev) > 0 {
				b.WriteString(mdFence(ev) + "\n")
			}
			fix := ck.Remediation
			if lang == "ko" && ck.RemediationKo != "" {
				fix = ck.RemediationKo
			}
			if fix != "" && !hinted[fix] {
				hinted[fix] = true
				label := "How to fix:"
				if lang == "ko" && ck.RemediationKo != "" {
					label = "조치 방법:"
				}
				// The rule's own guidance (or a pack's), written like any text from outside: as character references.
				fmt.Fprintf(&b, "**%s** %s\n\n", label, mdTextTo(fix, maxMarkdownFix))
			}
		}
		if !wrote && c.Reason != "" {
			fmt.Fprintf(&b, "%s\n\n", mdText(c.Reason))
		}
		b.WriteString("</details>\n\n")
	}
	_, err := io.WriteString(w, b.String())
	return err
}
