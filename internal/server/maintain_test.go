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

// A re-installed machine (new host ID, same name) is refused until the old host is deleted.
func TestDeleteHostLetsAReinstalledMachineStartAgain(t *testing.T) {
	f := newAPIFixture(t)
	ingest := token(t, f.store, ScopeIngest, "")
	web := fixture(t, "web-01.json")
	variant := func(hostID, scanID string) []byte {
		out := bytes.ReplaceAll(web, []byte(`"hostname": "web-01"`), []byte(`"hostname": "reinstalled", "hostId": "`+hostID+`"`))
		return bytes.ReplaceAll(out, []byte(`019a43c2-6f0e-7b51-9b5f-3c2e8d1a4f10`), []byte(scanID))
	}
	if code, out := post(t, f.srv, ingest, variant("old", "r-1")); code != 201 {
		t.Fatalf("%d %v", code, out)
	}
	code, out := post(t, f.srv, ingest, variant("new", "r-2"))
	if code != 409 || !strings.Contains(out["error"].(string), "host delete") {
		t.Fatalf("the new host ID: %d %v (the message should say how to resolve it)", code, out)
	}
	ctx := context.Background()
	hosts, err := f.store.HostList(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var id int64
	for _, h := range hosts {
		if h.Name == "reinstalled" {
			id = h.ID
		}
	}
	if id == 0 {
		t.Fatal("the host is not in the list")
	}
	if ok, err := f.store.DeleteHost(ctx, id); !ok || err != nil {
		t.Fatalf("delete: %v %v", ok, err)
	}
	if ok, _ := f.store.DeleteHost(ctx, id); ok {
		t.Error("a host was deleted twice")
	}
	if n := count(t, f.store, `SELECT COUNT(*) FROM scans WHERE scan_id = 'r-1'`); n != 0 {
		t.Errorf("%d scans of the deleted host remain", n)
	}
	if code, out := post(t, f.srv, ingest, variant("new", "r-3")); code != 201 {
		t.Errorf("after the deletion: %d %v", code, out)
	}
	if n := count(t, f.store, `SELECT COUNT(*) FROM audit WHERE action = 'host-deleted'`); n != 1 {
		t.Errorf("%d audit rows for the deletion", n)
	}
	if _, _, err := f.store.VerifyAudit(ctx); err != nil {
		t.Errorf("audit chain: %v", err)
	}
}
