package server

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// ingestAt stores a result of web-01 with a scan ID, received at the given time.
func ingestAt(t *testing.T, f *apiFixture, ingest string, id int, at time.Time) {
	t.Helper()
	f.clock = at
	doc := bytes.ReplaceAll(fixture(t, "web-01.json"), []byte(`019a43c2-6f0e-7b51-9b5f-3c2e8d1a4f10`), []byte("m-"+strconv.Itoa(id)))
	doc = bytes.ReplaceAll(doc, []byte(`"startedAt": "2026-11-02T12:00:00Z"`), []byte(`"startedAt": "`+at.Add(-time.Minute).Format(time.RFC3339)+`"`))
	if code, out := post(t, f.srv, ingest, doc); code != 201 {
		t.Fatalf("scan %d: %d %v", id, code, out)
	}
}

func TestPruneKeepsTheLatestScanOfEveryHost(t *testing.T) {
	f := newAPIFixture(t) // three scans an hour apart, from testNow
	ingest := token(t, f.store, ScopeIngest, "")
	day := 24 * time.Hour
	base := testNow.Add(10 * time.Hour)
	for i := range 5 {
		ingestAt(t, f, ingest, i, base.Add(time.Duration(i)*day))
	}
	f.clock = base.Add(5 * day)
	ctx := context.Background()
	before := count(t, f.store, `SELECT COUNT(*) FROM scans`)
	n, err := f.store.Prune(ctx, 2*day+time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 || count(t, f.store, `SELECT COUNT(*) FROM scans`) != before-n {
		t.Fatalf("pruned %d of %d", n, before)
	}
	// Every host still has its latest scan, and nothing derived is left without its scan.
	if got := count(t, f.store, `SELECT COUNT(*) FROM hosts h WHERE EXISTS (SELECT 1 FROM scans s WHERE s.host_row = h.id)`); got != count(t, f.store, `SELECT COUNT(*) FROM hosts`) {
		t.Error("a host lost all its scans")
	}
	if got := count(t, f.store, `SELECT COUNT(*) FROM scan_controls WHERE scan_row NOT IN (SELECT id FROM scans)`); got != 0 {
		t.Errorf("%d orphan control rows", got)
	}
	// Retention so short that everything is old still keeps one scan per host.
	if _, err := f.store.Prune(ctx, time.Nanosecond); err != nil {
		t.Fatal(err)
	}
	if hosts, scans := count(t, f.store, `SELECT COUNT(*) FROM hosts`), count(t, f.store, `SELECT COUNT(*) FROM scans`); hosts != scans {
		t.Errorf("%d hosts, %d scans: one latest scan per host expected", hosts, scans)
	}
	if count(t, f.store, `SELECT COUNT(*) FROM audit WHERE action = 'prune'`) == 0 {
		t.Error("the pruning was not audited")
	}
	if _, _, err := f.store.VerifyAudit(ctx); err != nil {
		t.Errorf("the audit chain broke: %v", err)
	}
	if _, err := f.store.Prune(ctx, 0); err == nil {
		t.Error("a zero retention was accepted")
	}
}

func TestBackupIsConsistentPrivateAndNeverOverwrites(t *testing.T) {
	f := newAPIFixture(t)
	path := filepath.Join(t.TempDir(), "copy.db")
	ctx := context.Background()
	if err := f.store.Backup(ctx, path); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm()&0o077 != 0 {
		t.Fatalf("backup: %v, mode %v", err, fi)
	}
	copyStore, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer copyStore.Close()
	if a, b := count(t, f.store, `SELECT COUNT(*) FROM scans`), count(t, copyStore, `SELECT COUNT(*) FROM scans`); a != b || a == 0 {
		t.Errorf("%d scans in the original, %d in the copy", a, b)
	}
	if _, _, err := copyStore.VerifyAudit(ctx); err != nil {
		t.Errorf("the copy's audit chain: %v", err)
	}
	if err := f.store.Backup(ctx, path); err == nil || !strings.Contains(err.Error(), "exists") {
		t.Errorf("an existing file was overwritten: %v", err)
	}
}

func TestStats(t *testing.T) {
	f := newAPIFixture(t)
	st, err := f.store.Stats(context.Background())
	if err != nil || st.Hosts != 2 || st.Scans != 3 || st.Credentials < 2 || st.Oldest == "" || st.Newest < st.Oldest {
		t.Errorf("stats = %+v, %v", st, err)
	}
}
