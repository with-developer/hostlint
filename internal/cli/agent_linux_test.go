//go:build linux

package cli

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/with-developer/vmsctl/internal/server"
)

// The agent polls a real server, and the scan that the dashboard asks for runs and comes back as the answer.
func TestAgentEndToEnd(t *testing.T) {
	store, err := server.OpenStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	srv := httptest.NewServer(server.New(server.Config{Store: store, PollHold: 100 * time.Millisecond, Rate: 100000}).Handler())
	t.Cleanup(srv.Close)
	ctx := context.Background()
	ingest, _, err := store.CreateCredential(ctx, server.ScopeIngest, "img-01", "img-01", 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("VMSCTL_TOKEN", ingest)
	root := fakeRoot(t)

	// The host has sent a result once.
	if code, _, stderr := run(ctx, t, "scan", "--root", root, "--push", srv.URL, "--fail-on", "none"); code != ExitOK {
		t.Fatalf("first scan: %d %s", code, stderr)
	}
	hosts, _, err := store.Hosts(ctx, server.HostFilter{})
	if err != nil || len(hosts) != 1 {
		t.Fatalf("hosts %v %v", hosts, err)
	}
	row := hosts[0].ID

	actx, stop := context.WithCancel(ctx)
	done := make(chan string, 1)
	go func() {
		_, _, stderr := run(actx, t, "agent", "--server", srv.URL, "--root", root, "--allow-profile", "kisa-2026")
		done <- stderr
	}()
	t.Cleanup(stop)

	// Ask once it is online.
	var jobID int64
	deadline := time.Now().Add(10 * time.Second)
	for jobID == 0 {
		if j, err := store.CreateJob(ctx, &server.Credential{ID: 1}, "test", row, "kisa-2026"); err == nil {
			jobID = j.ID
		} else if time.Now().After(deadline) {
			t.Fatalf("the agent did not come online: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	for {
		a, err := store.HostAgent(ctx, row)
		if err != nil {
			t.Fatal(err)
		}
		if a.Job != nil && a.Job.ID == jobID && a.Job.State == "done" {
			if a.Job.Scan == 0 || !a.Online {
				t.Errorf("done job without its scan: %+v %+v", a, a.Job)
			}
			break
		}
		if a.Job != nil && a.Job.State == "failed" {
			t.Fatalf("job failed: %s", a.Job.Error)
		}
		if time.Now().After(deadline) {
			t.Fatalf("job not done: %+v", a.Job)
		}
		time.Sleep(20 * time.Millisecond)
	}
	stop()
	select {
	case stderr := <-done:
		if !strings.Contains(stderr, "allowing kisa-2026") || !strings.Contains(stderr, "scanning with kisa-2026") {
			t.Errorf("agent log: %q", stderr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the agent did not stop")
	}
}
