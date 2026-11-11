package output

import (
	"encoding/csv"
	"io"
	"strconv"
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
// stops the formula. A spreadsheet that opens a CSV file shows that apostrophe (it hides one only when it is typed into a cell), so
// a value such as -rw-r--r-- appears with it: a visible mark is the price of a report that cannot run anything. Line breaks and control characters are escaped, as in the table.
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
		undecided := 0
		for _, ref := range c.Checks {
			ck := byRef[ref]
			if ck == nil {
				// A result that lacks the check a control names (a partial or filtered one): say so, never an empty row.
				look = append(look, ref)
				evidence = append(evidence, ref+": the result has no detail of this check")
				continue
			}
			if ck.Status == engine.StatusPass || ck.Status == engine.StatusNotApplicable {
				continue
			}
			// The fix comes from the first failed check before any cap, so a long list never hides it; a waived control has
			// been accepted: its evidence says what was, and there is nothing left to fix.
			if fix == "" && ck.Status == engine.StatusFail && c.Waiver == nil {
				fix = ck.Remediation
			}
			if len(look) >= maxCSVChecks {
				undecided++
				continue
			}
			look = append(look, ck.ID)
			for i, e := range ck.Evidence {
				if i >= maxCSVEvidence {
					evidence = append(evidence, ck.ID+": ... "+strconv.Itoa(len(ck.Evidence)-maxCSVEvidence)+" more in the JSON result")
					break
				}
				text := e.Key + " " + e.Text
				if e.Source != "" {
					text += " (" + e.Source + ")"
				}
				evidence = append(evidence, ck.ID+": "+oneLine(text))
			}
		}
		if undecided > 0 {
			look = append(look, "... "+strconv.Itoa(undecided)+" more")
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
