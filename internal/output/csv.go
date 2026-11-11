package output

import (
	"encoding/csv"
	"io"
	"strings"

	"github.com/with-developer/vmsctl/internal/engine"
)

// The CSV report is for a spreadsheet: one row per control, the columns an auditor files (what was checked, the verdict, the
// evidence, how to fix it). It starts with a byte order mark, which is what makes Excel read the Korean titles as UTF-8.
const (
	csvBOM = "\xef\xbb\xbf"
	// maxCSVCell is the longest text of one cell; the rest is cut. A spreadsheet cell holds 32,767 characters, and a page of
	// evidence is not what a row is for (the JSON has all of it).
	maxCSVCell = 2000
	// maxCSVEvidence is how many evidence lines of a check are kept, and maxCSVChecks how many undecided or failed checks of
	// a control give evidence.
	maxCSVEvidence = 3
	maxCSVChecks   = 5
)

var csvHeader = []string{"host", "profile", "control", "title", "title_ko", "severity", "status", "checks_to_look_at", "evidence", "how_to_fix", "waiver"}

// csvCell makes text safe for a spreadsheet. What a scan prints comes from the scanned host (a file name, a value in a
// configuration) or from a pack, and a spreadsheet takes a cell that starts with = + - @ (or a tab or a carriage return) for a
// formula: a value such as =HYPERLINK(...) would then run when the report is opened. Such a cell starts with an apostrophe, which
// the spreadsheet does not show and which stops the formula. Line breaks and control characters are escaped, as in the table.
func csvCell(s string) string {
	s = clipTo(oneLine(s), maxCSVCell)
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

func writeCSV(w io.Writer, res *engine.Result) error {
	if _, err := io.WriteString(w, csvBOM); err != nil {
		return err
	}
	cw := csv.NewWriter(w)
	if err := cw.Write(csvHeader); err != nil {
		return err
	}
	byRef := map[string]*engine.CheckResult{}
	for i := range res.Checks {
		byRef[res.Checks[i].Ref] = &res.Checks[i]
	}
	for _, c := range res.Controls {
		var look, evidence []string
		var fix string
		for _, ref := range c.Checks {
			ck := byRef[ref]
			if ck == nil || ck.Status == engine.StatusPass || ck.Status == engine.StatusNotApplicable {
				continue
			}
			if len(look) >= maxCSVChecks {
				continue
			}
			look = append(look, ck.ID)
			for i, e := range ck.Evidence {
				if i >= maxCSVEvidence {
					break
				}
				text := e.Key + " " + e.Text
				if e.Source != "" {
					text += " (" + e.Source + ")"
				}
				evidence = append(evidence, ck.ID+": "+oneLine(text))
			}
			if fix == "" && ck.Status == engine.StatusFail {
				fix = ck.Remediation
			}
		}
		waiver := ""
		if c.Waiver != nil {
			waiver = c.Waiver.Reason + " (until " + c.Waiver.Expires + ")"
		}
		row := []string{
			csvCell(res.Host.Hostname), csvCell(c.Profile), csvCell(c.ID), csvCell(c.Title), csvCell(c.TitleKo),
			csvCell(string(c.Severity)), csvCell(string(c.Status)),
			csvCell(strings.Join(look, "; ")), csvCell(strings.Join(evidence, " | ")), csvCell(fix), csvCell(waiver),
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}
