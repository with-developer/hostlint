package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/with-developer/hostlint/internal/engine"
)

// Limits of the Markdown report: it is for a page a person reads (a job summary, a pull request comment),
// not for the whole result, which is the JSON.
const (
	maxMarkdownControls = 200
	maxMarkdownDetails  = 30
	maxMarkdownEvidence = 5
)

// mdText makes text safe for Markdown that GitHub, GitLab and others render: what a scan prints comes from
// the scanned host (a file name, a value in a configuration) or from a pack, and must not become a link, an
// image, HTML, a mention or an issue reference. Every character that means something is written as a
// character reference, which shows as the character and is nothing else; control characters and line
// breaks are escaped as in the table.
func mdText(s string) string {
	s = oneLine(s)
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
		default:
			b.WriteRune(r)
		}
	}
	// "www." makes a link of what follows it.
	return strings.NewReplacer("www.", "www&#46;", "WWW.", "WWW&#46;", "Www.", "Www&#46;").Replace(b.String())
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

func writeMarkdown(w io.Writer, res *engine.Result) error {
	var b strings.Builder
	host := oneLine(res.Host.Hostname)
	if host == "" {
		host = "(no host name)"
	}
	fmt.Fprintf(&b, "## hostlint: %s\n\n", mdText(host))
	var profiles []string
	for _, pr := range res.Profiles {
		profiles = append(profiles, mdText(pr.ID))
	}
	line := fmt.Sprintf("hostlint %s &middot; %s", mdText(res.Scan.Tool.Version), strings.Join(profiles, ", "))
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
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n", mdText(c.Profile), mdText(c.ID), c.Severity, c.Status, mdText(c.Title))
		} else {
			fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", mdText(c.ID), c.Severity, c.Status, mdText(c.Title))
		}
	}

	checks := map[string]engine.CheckResult{}
	for _, c := range res.Checks {
		checks[c.Ref] = c
	}
	b.WriteString("\n### Details\n\n")
	for i, c := range attention {
		if i == maxMarkdownDetails {
			fmt.Fprintf(&b, "%d more controls have no details here.\n", len(attention)-i)
			break
		}
		fmt.Fprintf(&b, "<details>\n<summary>%s %s &mdash; %s</summary>\n\n", mdText(c.ID), c.Status, mdText(c.Title))
		if c.Reason != "" && (len(c.Checks) == 0 || c.Waiver != nil) {
			fmt.Fprintf(&b, "%s\n\n", mdText(c.Reason))
		}
		for _, ref := range c.Checks {
			ck, ok := checks[ref]
			if !ok || ck.Status == engine.StatusPass || ck.Status == engine.StatusNotApplicable {
				continue
			}
			fmt.Fprintf(&b, "**%s** %s &mdash; %s\n\n", mdText(ck.ID), ck.Status, mdText(ck.Title))
			if ck.Reason != "" && ck.Status != engine.StatusFail {
				fmt.Fprintf(&b, "%s\n\n", mdText(ck.Reason))
			}
			var ev []string
			for j, e := range ck.Evidence {
				if j == maxMarkdownEvidence {
					ev = append(ev, fmt.Sprintf("... and %d more", len(ck.Evidence)-j))
					break
				}
				text := oneLine(e.Text)
				if src := oneLine(e.Source); src != "" && !strings.Contains(text, src) {
					text += "  [" + src + "]"
				}
				ev = append(ev, text)
			}
			if len(ev) > 0 {
				b.WriteString(mdFence(ev) + "\n")
			}
		}
		b.WriteString("</details>\n\n")
	}
	_, err := io.WriteString(w, b.String())
	return err
}
