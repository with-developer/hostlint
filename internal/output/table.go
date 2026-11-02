package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/with-developer/hostlint/internal/engine"
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

	host := res.Host.Hostname
	if res.Host.OS.Name != "" {
		host += " (" + res.Host.OS.Name + ")"
	}
	profiles := make([]string, 0, len(res.Profiles))
	for _, pr := range res.Profiles {
		profiles = append(profiles, pr.ID)
	}
	fmt.Fprintf(&b, "%s %s · %s · %s\n", p.paint(bold, "hostlint"), res.Scan.Tool.Version, strings.Join(profiles, ", "), host)
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
		fmt.Fprintf(&b, "%s %-6s %-6s %s %s\n",
			p.paint(st.color, st.mark), p.paint(st.color, string(ctl.Status)), ctl.ID, ctl.Title, p.paint(dim, "["+string(ctl.Severity)+"]"))
		for _, ref := range ctl.Checks {
			c, ok := checks[ref]
			if !ok || (!opts.Verbose && c.Status == engine.StatusPass) {
				continue
			}
			writeCheck(&b, p, c)
		}
	}
	if shown == 0 {
		b.WriteString(p.paint(green, "Every control passed or does not apply.") + "\n")
	}

	for _, pr := range res.Profiles {
		sum := res.Summary[pr.ID]
		var parts []string
		total := 0
		for _, st := range engine.AllStatuses {
			if n := sum.Controls[st]; n > 0 {
				total += n
				parts = append(parts, p.paint(statusStyle[st].color, fmt.Sprintf("%d %s", n, st)))
			}
		}
		fmt.Fprintf(&b, "\n%s: %d controls — %s\n", pr.ID, total, strings.Join(parts, ", "))
	}
	if !opts.Verbose {
		b.WriteString(p.paint(dim, "Passing and not-applicable controls are hidden; use --verbose to list them.") + "\n")
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func writeCheck(b *strings.Builder, p painter, c engine.CheckResult) {
	st := statusStyle[c.Status]
	fmt.Fprintf(b, "    %s %s %s\n", p.paint(st.color, st.mark), c.ID, p.paint(dim, "— "+c.Title))
	if c.Reason != "" && c.Status != engine.StatusFail {
		fmt.Fprintf(b, "        %s\n", oneLine(c.Reason))
	}
	if c.Status == engine.StatusPass || c.Status == engine.StatusNotApplicable {
		return
	}
	for i, ev := range c.Evidence {
		if i == maxEvidenceLines {
			fmt.Fprintf(b, "        %s\n", p.paint(dim, fmt.Sprintf("… and %d more", len(c.Evidence)-i+c.EvidenceOmitted)))
			break
		}
		line := ev.Text
		if ev.Source != "" && !strings.Contains(line, ev.Source) {
			line += "  " + p.paint(dim, ev.Source)
		}
		fmt.Fprintf(b, "        %s\n", oneLine(line))
	}
}

// oneLine keeps evidence on a single terminal line.
func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}
