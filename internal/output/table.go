package output

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode"

	"github.com/with-developer/vmsctl/internal/engine"
)

// ANSI styles for the table.
const (
	reset  = "\x1b[0m"
	bold   = "\x1b[1m"
	dim    = "\x1b[2m"
	red    = "\x1b[31m"
	green  = "\x1b[32m"
	yellow = "\x1b[33m"
	blue   = "\x1b[34m"
	purple = "\x1b[35m"
)

var statusStyle = map[engine.Status]struct{ mark, color string }{
	engine.StatusFail:          {"✗", red},
	engine.StatusError:         {"!", purple},
	engine.StatusManual:        {"?", yellow},
	engine.StatusWaived:        {"~", blue},
	engine.StatusPass:          {"✓", green},
	engine.StatusNotApplicable: {"-", dim},
}

// maxEvidenceLines bounds the evidence shown under each check in the table.
const maxEvidenceLines = 3

type painter struct{ on bool }

func (p painter) paint(style, s string) string {
	if !p.on || style == "" {
		return s
	}
	return style + s + reset
}

func writeTable(w io.Writer, res *engine.Result, opts Options) error {
	p := painter{on: opts.Color}
	var b strings.Builder
	checks := map[string]engine.CheckResult{}
	for _, c := range res.Checks {
		checks[c.Ref] = c
	}

	host := oneLine(res.Host.Hostname)
	if host == "" {
		host = "(no host name)" // a mounted image often has none
	}
	if name := oneLine(res.Host.OS.Name); name != "" {
		host += " (" + name + ")"
	}
	profiles := make([]string, 0, len(res.Profiles))
	for _, pr := range res.Profiles {
		profiles = append(profiles, pr.ID)
	}
	fmt.Fprintf(&b, "%s %s · %s · %s\n", p.paint(bold, "vmsctl"), res.Scan.Tool.Version, strings.Join(profiles, ", "), host)
	if res.Scan.Target.Kind == "root" {
		fmt.Fprintf(&b, "%s\n", p.paint(dim, "mounted root "+res.Scan.Target.Root+": live checks are not available"))
	}
	if !res.Host.OS.Supported {
		fmt.Fprintf(&b, "%s\n", p.paint(yellow, "this OS version is not in the tested matrix; results are best-effort"))
	}
	if res.Scan.Privileges.EUID != 0 {
		fmt.Fprintf(&b, "%s\n", p.paint(yellow, "not running as root: checks that need protected files will report ERROR"))
	}
	b.WriteString("\n")

	shown := 0
	for _, ctl := range res.Controls {
		if !opts.Verbose && (ctl.Status == engine.StatusPass || ctl.Status == engine.StatusNotApplicable) {
			continue
		}
		shown++
		st := statusStyle[ctl.Status]
		fmt.Fprintf(&b, "%s %s %-6s %s %s\n",
			p.paint(st.color, st.mark), p.paint(st.color, fmt.Sprintf("%-6s", ctl.Status)), oneLine(ctl.ID), oneLine(titleIn(opts.Lang, ctl.Title, ctl.TitleKo)), p.paint(dim, "["+string(ctl.Severity)+"]"))
		// A control without checks (it needs a person) has nothing else to
		// say what to do; a waived control says why it was accepted.
		if ctl.Reason != "" && (len(ctl.Checks) == 0 || ctl.Waiver != nil) {
			fmt.Fprintf(&b, "    %s\n", p.paint(dim, oneLine(ctl.Reason)))
		}
		for _, ref := range ctl.Checks {
			c, ok := checks[ref]
			// Checks that pass or do not apply say nothing about why the control
			// fails; --verbose lists them.
			if !ok || (!opts.Verbose && (c.Status == engine.StatusPass || c.Status == engine.StatusNotApplicable)) {
				continue
			}
			writeCheck(&b, p, c, opts.Lang)
		}
	}
	if shown == 0 {
		b.WriteString(p.paint(green, "Every control passed or does not apply.") + "\n")
	}

	for _, pr := range res.Profiles {
		sum := res.Summary[pr.ID]
		var parts []string
		total := 0
		for _, st := range engine.Statuses() {
			if n := sum.Controls[st]; n > 0 {
				total += n
				parts = append(parts, p.paint(statusStyle[st].color, fmt.Sprintf("%d %s", n, st)))
			}
		}
		fmt.Fprintf(&b, "\n%s: %d controls — %s\n", pr.ID, total, strings.Join(parts, ", "))
	}
	for _, w := range res.Waivers {
		fmt.Fprintf(&b, "%s\n", p.paint(yellow, fmt.Sprintf("waiver for %s %s (until %s) not applied: %s", w.Scope, w.ID, w.Expires, oneLine(w.Problem))))
	}
	for _, a := range res.Attestations {
		fmt.Fprintf(&b, "%s\n", p.paint(yellow, fmt.Sprintf("attestation of %s by %s (until %s) not applied: %s", a.Check, a.By, a.Expires, oneLine(a.Problem))))
	}
	if !opts.Verbose {
		b.WriteString(p.paint(dim, "Passing and not-applicable controls are hidden; use --verbose to list them.") + "\n")
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func writeCheck(b *strings.Builder, p painter, c engine.CheckResult, lang string) {
	st := statusStyle[c.Status]
	fmt.Fprintf(b, "    %s %s %s\n", p.paint(st.color, st.mark), oneLine(c.ID), p.paint(dim, "— "+oneLine(titleIn(lang, c.Title, c.TitleKo))))
	if c.Reason != "" && c.Status != engine.StatusFail {
		fmt.Fprintf(b, "        %s\n", oneLine(titleIn(lang, c.Reason, c.ReasonKo)))
	}
	if c.Status == engine.StatusPass || c.Status == engine.StatusNotApplicable {
		return
	}
	shown := min(len(c.Evidence), maxEvidenceLines)
	for _, ev := range c.Evidence[:shown] {
		line := oneLine(ev.Text)
		if src := oneLine(ev.Source); src != "" && !strings.Contains(line, src) {
			line += "  " + p.paint(dim, src)
		}
		fmt.Fprintf(b, "        %s\n", line)
	}
	if more := len(c.Evidence) - shown + c.EvidenceOmitted; more > 0 {
		fmt.Fprintf(b, "        %s\n", p.paint(dim, fmt.Sprintf("… and %d more", more)))
	}
}

// oneLine makes text from the host safe for one terminal line: runs of
// whitespace become one space, and characters that are not printable are
// escaped, so a file or account name cannot move the cursor, change colors
// or reorder the line.
func oneLine(s string) string {
	var b strings.Builder
	space := false
	for _, r := range s {
		switch {
		case unicode.IsSpace(r):
			space = b.Len() > 0
			continue
		case space:
			b.WriteByte(' ')
			space = false
		}
		if unicode.IsGraphic(r) {
			b.WriteRune(r)
			continue
		}
		q := strconv.QuoteRuneToGraphic(r)
		b.WriteString(q[1 : len(q)-1])
	}
	return b.String()
}
