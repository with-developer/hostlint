package output

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/with-developer/hostlint/internal/engine"
)

func readFixture(t *testing.T, name string) *engine.Result {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", "report", name))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	res, err := ReadResult(f)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func ids(list []ControlChange) string {
	var out []string
	for _, c := range list {
		out = append(out, c.ID)
	}
	return strings.Join(out, ",")
}

func TestDiffResults(t *testing.T) {
	older, newer := readFixture(t, "web-01-old.json"), readFixture(t, "web-01.json")
	d := DiffResults("old.json", older, "new.json", newer)
	if ids(d.Regressed) != "U-01" || len(d.Fixed)+len(d.Changed)+len(d.Added)+len(d.Removed) != 0 || d.Unchanged != 4 || len(d.Notes) != 0 {
		t.Fatalf("diff = %+v", d)
	}
	c := d.Regressed[0]
	if c.Old != engine.StatusPass || c.New != engine.StatusFail || len(c.Checks) != 1 || c.Checks[0].Ref != "ssh.permit-root-login" {
		t.Errorf("control change = %+v", c)
	}

	// The other way round, the same change is a fix, and nothing is lost.
	back := DiffResults("new.json", newer, "old.json", older)
	if ids(back.Fixed) != "U-01" || len(back.Regressed) != 0 || len(back.Notes) != 1 || !strings.Contains(back.Notes[0], "changes read backwards") {
		t.Errorf("reversed diff = %+v", back)
	}

	same := DiffResults("a", newer, "b", newer)
	if len(same.Regressed)+len(same.Fixed)+len(same.Changed) != 0 || same.Unchanged != len(newer.Controls) {
		t.Errorf("a result against itself changed: %+v", same)
	}
}

// Different hosts and revisions are compared with a note; controls found in one result only are added or removed.
func TestDiffDifferentHostsAndRevisions(t *testing.T) {
	d := DiffResults("web.json", readFixture(t, "web-01.json"), "db.json", readFixture(t, "db-01.json"))
	notes := strings.Join(d.Notes, "|")
	if !strings.Contains(notes, "different hosts (web-01 and db-01)") || !strings.Contains(notes, "revision 1 to 2") {
		t.Errorf("notes = %q", notes)
	}
	if len(d.Added)+len(d.Removed) == 0 {
		t.Errorf("no control added or removed: %+v", d)
	}
}

// FAIL to ERROR is a change, not a regression; ERROR to FAIL neither.
func TestDiffClassification(t *testing.T) {
	mk := func(status engine.Status) *engine.Result {
		return &engine.Result{
			Host:     engine.HostInfo{Hostname: "h"},
			Scan:     engine.ScanInfo{StartedAt: "2026-11-01T00:00:00Z"},
			Controls: []engine.ControlResult{{Profile: "p", ID: "U-1", Title: "t", Severity: engine.SeverityHigh, Status: status, Checks: []string{}}},
		}
	}
	for _, tt := range []struct {
		old, new engine.Status
		want     string // regressed, fixed or changed
	}{
		{engine.StatusPass, engine.StatusFail, "regressed"},
		{engine.StatusManual, engine.StatusError, "regressed"},
		{engine.StatusNotApplicable, engine.StatusFail, "regressed"},
		{engine.StatusFail, engine.StatusPass, "fixed"},
		{engine.StatusError, engine.StatusWaived, "fixed"},
		{engine.StatusFail, engine.StatusError, "changed"},
		{engine.StatusError, engine.StatusFail, "changed"},
		{engine.StatusPass, engine.StatusManual, "changed"},
		{engine.StatusManual, engine.StatusPass, "changed"},
	} {
		d := DiffResults("a", mk(tt.old), "b", mk(tt.new))
		got := map[string]int{"regressed": len(d.Regressed), "fixed": len(d.Fixed), "changed": len(d.Changed)}
		if got[tt.want] != 1 || got["regressed"]+got["fixed"]+got["changed"] != 1 {
			t.Errorf("%s → %s: %v, want %s", tt.old, tt.new, got, tt.want)
		}
	}
}

func TestWriteDiff(t *testing.T) {
	d := DiffResults("old.json", readFixture(t, "web-01-old.json"), "new.json", readFixture(t, "web-01.json"))
	var table bytes.Buffer
	if err := WriteDiff(&table, d, "table", Options{}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"hostlint diff web-01", "Regressed (1)", "U-01", "PASS → FAIL", "1 regressed, 0 fixed"} {
		if !strings.Contains(table.String(), want) {
			t.Errorf("table lacks %q:\n%s", want, table.String())
		}
	}
	var js bytes.Buffer
	if err := WriteDiff(&js, d, "json", Options{}); err != nil {
		t.Fatal(err)
	}
	var back Diff
	if err := json.Unmarshal(js.Bytes(), &back); err != nil || len(back.Regressed) != 1 {
		t.Errorf("json: %v, %+v", err, back)
	}
	if err := WriteDiff(&bytes.Buffer{}, d, "yaml", Options{}); err == nil {
		t.Error("unknown format accepted")
	}
	// Text from a result cannot drive the terminal.
	d.New.Host = "evil\x1b[2J"
	var esc bytes.Buffer
	if err := WriteDiff(&esc, d, "table", Options{}); err != nil || strings.Contains(esc.String(), "\x1b") {
		t.Errorf("escape sequence in the table: %q", esc.String())
	}
}
