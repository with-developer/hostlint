package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type agentFixture struct {
	*apiFixture
	agent    string // an ingest token bound to web-01
	operator string
	host     int64
}

func newAgentFixture(t *testing.T) *agentFixture {
	t.Helper()
	f := &agentFixture{apiFixture: newAPIFixture(t)}
	f.srv.cfg.PollHold = 30 * time.Millisecond
	f.agent = token(t, f.store, ScopeIngest, "web-01")
	f.operator = token(t, f.store, ScopeOperator, "")
	if err := f.store.db.QueryRow(`SELECT id FROM hosts WHERE name = 'web-01'`).Scan(&f.host); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *agentFixture) post(path, tok, body string, hdr map[string]string) (int, map[string]any) {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	f.srv.Handler().ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func (f *agentFixture) poll(tok string, allow ...string) (int, map[string]any) {
	b, _ := json.Marshal(map[string]any{"allow": allow})
	return f.post("/api/v1/agent/poll", tok, string(b), nil)
}

func (f *agentFixture) request(tok, profile string) (int, map[string]any) {
	return f.post("/api/v1/hosts/"+itoa(f.host)+"/scan", tok, `{"profile":"`+profile+`"}`, nil)
}

func jobID(t *testing.T, out map[string]any) string {
	t.Helper()
	job, ok := out["job"].(map[string]any)
	if !ok {
		t.Fatalf("no job in %v", out)
	}
	return itoa(int64(job["id"].(float64)))
}

func TestAgentJobLifecycle(t *testing.T) {
	f := newAgentFixture(t)
	if code, _ := f.poll(f.agent, "kisa-2026"); code != http.StatusNoContent {
		t.Fatalf("an idle poll: %d", code)
	}
	code, out := f.request(f.operator, "kisa-2026")
	if code != http.StatusAccepted {
		t.Fatalf("request: %d %v", code, out)
	}
	id := jobID(t, out)
	code, out = f.poll(f.agent, "kisa-2026")
	if code != http.StatusOK || jobID(t, out) != id || out["job"].(map[string]any)["profile"] != "kisa-2026" {
		t.Fatalf("poll: %d %v", code, out)
	}
	// The job is the agent's now: a second poll finds nothing.
	if code, _ := f.poll(f.agent, "kisa-2026"); code != http.StatusNoContent {
		t.Errorf("claimed twice: %d", code)
	}
	// The result that answers it finishes it.
	doc := bytes.ReplaceAll(laterScan(fixture(t, "web-01.json"), 30), []byte(`019a43c2-6f0e-7b51-9b5f-3c2e8d1a4f10`), []byte(`019a43c2-6f0e-7b51-9b5f-3c2e8d1a4f77`))
	code, out = f.post("/api/v1/results", f.agent, string(doc), map[string]string{"X-Hostlint-Job": id})
	if code != http.StatusCreated {
		t.Fatalf("ingest: %d %v", code, out)
	}
	a, err := f.store.HostAgent(context.Background(), f.host)
	if err != nil {
		t.Fatal(err)
	}
	if !a.Online || a.Job == nil || a.Job.State != "done" || a.Job.Scan == 0 || a.Job.FinishedAt == "" {
		t.Errorf("agent after the result: %+v %+v", a, a.Job)
	}
	if got := count(t, f.store, `SELECT COUNT(*) FROM audit WHERE action = 'scan-requested'`); got != 1 {
		t.Errorf("audit entries of the request: %d", got)
	}
	// The host page says so.
	var info AgentInfo
	f.json(t, "/api/v1/hosts/"+itoa(f.host)+"/agent", &info)
	if !info.Online || info.Profiles[0] != "kisa-2026" || info.Job == nil || info.Job.State != "done" {
		t.Errorf("host agent: %+v", info)
	}
	if code, _ := f.get(t, f.api, "/api/v1/hosts/999/agent"); code != http.StatusNotFound {
		t.Errorf("no such host: %d", code)
	}
	if code, _ := f.get(t, "", "/api/v1/hosts/1/agent"); code != http.StatusUnauthorized {
		t.Errorf("no token: %d", code)
	}
}

func TestAgentPollWakesOnRequest(t *testing.T) {
	f := newAgentFixture(t)
	f.srv.cfg.PollHold = 5 * time.Second
	first := make(chan [2]any)
	go func() {
		code, out := f.poll(f.agent, "kisa-2026")
		first <- [2]any{code, out}
	}()
	// The poll registers the agent; wait until it has, then ask.
	deadline := time.Now().Add(3 * time.Second)
	for {
		if code, _ := f.request(f.operator, "kisa-2026"); code == http.StatusAccepted {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the agent never became online")
		}
		time.Sleep(5 * time.Millisecond)
	}
	select {
	case got := <-first:
		if got[0] != http.StatusOK {
			t.Errorf("the held poll: %v", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the held poll was not woken")
	}
}

func TestScanRequestRules(t *testing.T) {
	f := newAgentFixture(t)
	// No agent has polled: offline.
	if code, _ := f.request(f.operator, "kisa-2026"); code != http.StatusConflict {
		t.Errorf("offline: %d", code)
	}
	f.poll(f.agent, "kisa-2026")
	for name, tc := range map[string]struct {
		tok  string
		want int
	}{
		"no token":   {"", http.StatusUnauthorized},
		"read token": {f.api, http.StatusForbidden},
		"ingest":     {f.agent, http.StatusUnauthorized},
		"garbage":    {"hlt_opr_nope", http.StatusUnauthorized},
	} {
		if code, _ := f.request(tc.tok, "kisa-2026"); code != tc.want {
			t.Errorf("%s: %d, want %d", name, code, tc.want)
		}
	}
	if code, _ := f.request(f.operator, "essentials"); code != http.StatusConflict {
		t.Errorf("a profile the agent does not allow: %d", code)
	}
	if code, _ := f.request(f.operator, "KISA; DROP"); code != http.StatusBadRequest {
		t.Errorf("a malformed profile: %d", code)
	}
	if code, _ := f.post("/api/v1/hosts/"+itoa(f.host)+"/scan", f.operator, `profile=kisa-2026`, map[string]string{"Content-Type": "text/plain"}); code != http.StatusBadRequest {
		t.Errorf("not JSON: %d", code)
	}
	if code, _ := f.post("/api/v1/hosts/999/scan", f.operator, `{"profile":"kisa-2026"}`, nil); code != http.StatusNotFound {
		t.Errorf("no such host: %d", code)
	}
	if code, _ := f.request(f.operator, "kisa-2026"); code != http.StatusAccepted {
		t.Fatalf("first request: %d", code)
	}
	// One at a time, and one a minute.
	if code, _ := f.request(f.operator, "kisa-2026"); code != http.StatusTooManyRequests {
		t.Errorf("pending: %d", code)
	}
	f.poll(f.agent, "kisa-2026") // claims it
	f.clock = f.clock.Add(30 * time.Second)
	if code, _ := f.request(f.operator, "kisa-2026"); code != http.StatusTooManyRequests {
		t.Errorf("claimed and unfinished: %d", code)
	}
	// An agent that is scanning does not poll, and still shows as connected while its job is open.
	f.clock = f.clock.Add(agentOnlineFor + time.Second)
	if code, _ := f.request(f.operator, "kisa-2026"); code != http.StatusConflict {
		t.Errorf("a silent agent: %d", code)
	}
	a, _ := f.store.HostAgent(context.Background(), f.host)
	if !a.Online || a.Job == nil || a.Job.State != "claimed" {
		t.Errorf("a scanning agent: %+v %+v", a, a.Job)
	}
	// A job nobody finished reads as expired, and then the host is offline.
	f.clock = f.clock.Add(jobExpiresAfter)
	a, _ = f.store.HostAgent(context.Background(), f.host)
	if a.Online || a.Job.State != "expired" {
		t.Errorf("after the limit: %+v %+v", a, a.Job)
	}
	f.poll(f.agent, "kisa-2026")
	if code, _ := f.request(f.operator, "kisa-2026"); code != http.StatusAccepted {
		t.Errorf("after expiry: %d", code)
	}
	// A request nobody took expires too, whatever the poll finds.
	f.poll(f.agent, "kisa-2026") // takes it
	f.clock = f.clock.Add(2 * time.Minute)
	if code, _ := f.request(f.operator, "kisa-2026"); code != http.StatusTooManyRequests {
		t.Errorf("a job taken two minutes ago: %d", code)
	}
}

// A job whose answer never reached the agent is failed when the agent asks again, not left to block the host.
func TestLostClaimIsFailed(t *testing.T) {
	f := newAgentFixture(t)
	f.poll(f.agent, "kisa-2026")
	_, out := f.request(f.operator, "kisa-2026")
	id := jobID(t, out)
	if code, _ := f.poll(f.agent, "kisa-2026"); code != http.StatusOK { // claimed; suppose the answer was lost
		t.Fatal(code)
	}
	f.clock = f.clock.Add(time.Minute + time.Second)
	f.poll(f.agent, "kisa-2026")
	a, _ := f.store.HostAgent(context.Background(), f.host)
	if a.Job.ID != 0 && itoa(a.Job.ID) != id || a.Job.State != "failed" || !strings.Contains(a.Job.Error, "never took") {
		t.Errorf("job: %+v", a.Job)
	}
	if code, _ := f.request(f.operator, "kisa-2026"); code != http.StatusAccepted {
		t.Errorf("a new request: %d", code)
	}
}

// A request nobody took expires.
func TestUntakenRequestExpires(t *testing.T) {
	f := newAgentFixture(t)
	f.poll(f.agent, "kisa-2026")
	if code, _ := f.request(f.operator, "kisa-2026"); code != http.StatusAccepted {
		t.Fatal(code)
	}
	f.clock = f.clock.Add(jobExpiresAfter + time.Second)
	if code, _ := f.poll(f.agent, "kisa-2026"); code != http.StatusNoContent {
		t.Errorf("an expired job was handed out: %d", code)
	}
	if a, _ := f.store.HostAgent(context.Background(), f.host); a.Job.State != "expired" {
		t.Errorf("job: %+v", a.Job)
	}
}

func TestAgentPollAuth(t *testing.T) {
	f := newAgentFixture(t)
	for name, tc := range map[string]struct {
		tok  string
		want int
	}{
		"no token": {"", http.StatusUnauthorized},
		"api":      {f.api, http.StatusUnauthorized},
		"operator": {f.operator, http.StatusUnauthorized},
		"any host": {token(t, f.store, ScopeIngest, ""), http.StatusConflict},
		"unknown":  {token(t, f.store, ScopeIngest, "ghost-01"), http.StatusConflict},
	} {
		if code, _ := f.poll(tc.tok, "kisa-2026"); code != tc.want {
			t.Errorf("%s: %d, want %d", name, code, tc.want)
		}
	}
	for name, body := range map[string]string{
		"empty":     `{"allow":[]}`,
		"bad id":    `{"allow":["../x"]}`,
		"too many":  `{"allow":["a","b","c","d","e","f","g","h","i"]}`,
		"not json":  `nope`,
		"no allows": `{}`,
	} {
		if code, _ := f.post("/api/v1/agent/poll", f.agent, body, nil); code != http.StatusBadRequest {
			t.Errorf("%s: %d", name, code)
		}
	}
	if code, _ := f.post("/api/v1/agent/poll", f.agent, `{"allow":["kisa-2026"]}`, map[string]string{"Content-Type": "text/plain"}); code != http.StatusUnsupportedMediaType {
		t.Errorf("not JSON: %d", code)
	}
	// A token bound to another host cannot touch web-01's jobs.
	other := token(t, f.store, ScopeIngest, "db-01")
	f.poll(f.agent, "kisa-2026")
	_, out := f.request(f.operator, "kisa-2026")
	id := jobID(t, out)
	f.poll(f.agent, "kisa-2026")
	if code, _ := f.post("/api/v1/agent/jobs/"+id+"/fail", other, `{"error":"mine now"}`, nil); code != http.StatusOK {
		t.Fatalf("fail with another host's token: %d", code)
	}
	if a, _ := f.store.HostAgent(context.Background(), f.host); a.Job.State != "claimed" {
		t.Errorf("another host's token changed the job: %+v", a.Job)
	}
	// The result of another host naming the job finishes nothing either.
	doc := bytes.ReplaceAll(fixture(t, "db-01.json"), []byte(`"startedAt": "2026-11-02T12:00:00Z"`), []byte(`"startedAt": "2026-11-02T12:40:00Z"`))
	doc = bytes.ReplaceAll(doc, []byte(`019a43c2-6f0e-7b51-9b5f-3c2e8d1a4f20`), []byte(`019a43c2-6f0e-7b51-9b5f-3c2e8d1a4f88`))
	f.post("/api/v1/results", other, string(doc), map[string]string{"X-Hostlint-Job": id})
	if a, _ := f.store.HostAgent(context.Background(), f.host); a.Job.State != "claimed" {
		t.Errorf("another host's result finished the job: %+v", a.Job)
	}
	// Its own agent can fail it, with a message that is printable.
	if code, _ := f.post("/api/v1/agent/jobs/"+id+"/fail", f.agent, "{\"error\":\"bad\\u001b[31m\"}", nil); code != http.StatusBadRequest {
		t.Errorf("control characters: %d", code)
	}
	if code, _ := f.post("/api/v1/agent/jobs/"+id+"/fail", f.agent, `{"error":"profile not found"}`, nil); code != http.StatusOK {
		t.Fatalf("fail: %d", code)
	}
	if a, _ := f.store.HostAgent(context.Background(), f.host); a.Job.State != "failed" || a.Job.Error != "profile not found" {
		t.Errorf("job: %+v", a.Job)
	}
}

// A session may ask for a scan only from a page of this site: JSON, an Origin that is the site, and an operator.
func TestScanRequestBySession(t *testing.T) {
	f := newAgentFixture(t)
	f.poll(f.agent, "kisa-2026")
	login := func(tok string) *http.Cookie {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/login", strings.NewReader(`{"token":"`+tok+`"}`))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		f.srv.Handler().ServeHTTP(rec, req)
		for _, c := range rec.Result().Cookies() {
			if c.Name == SessionCookie {
				return c
			}
		}
		t.Fatalf("no session for %s: %d %s", tok[:8], rec.Code, rec.Body)
		return nil
	}
	ask := func(c *http.Cookie, origin, ct string) int {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/hosts/"+itoa(f.host)+"/scan", strings.NewReader(`{"profile":"kisa-2026"}`))
		req.Host = "hostlint.example.org"
		req.Header.Set("Content-Type", ct)
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		req.AddCookie(c)
		rec := httptest.NewRecorder()
		f.srv.Handler().ServeHTTP(rec, req)
		return rec.Code
	}
	viewer, op := login(f.api), login(f.operator)
	site := "https://hostlint.example.org"
	if code := ask(op, "", "application/json"); code != http.StatusUnauthorized {
		t.Errorf("no Origin: %d", code)
	}
	if code := ask(op, "https://evil.example", "application/json"); code != http.StatusUnauthorized {
		t.Errorf("another site's Origin: %d", code)
	}
	if code := ask(op, "https://hostlint.example.org.evil.example", "application/json"); code != http.StatusUnauthorized {
		t.Errorf("a look-alike Origin: %d", code)
	}
	if code := ask(op, site, "text/plain"); code != http.StatusUnauthorized {
		t.Errorf("not JSON: %d", code)
	}
	if code := ask(viewer, site, "application/json"); code != http.StatusForbidden {
		t.Errorf("a viewer's session: %d", code)
	}
	if code := ask(op, site, "application/json"); code != http.StatusAccepted {
		t.Errorf("an operator's session: %d", code)
	}
	// The session endpoint says who may ask.
	for _, tc := range []struct {
		c    *http.Cookie
		want bool
	}{{viewer, false}, {op, true}} {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/session", nil)
		req.AddCookie(tc.c)
		rec := httptest.NewRecorder()
		f.srv.Handler().ServeHTTP(rec, req)
		var got map[string]bool
		_ = json.Unmarshal(rec.Body.Bytes(), &got)
		if got["canScan"] != tc.want {
			t.Errorf("canScan: %v, want %v", got, tc.want)
		}
	}
}

func TestOperatorTokenReads(t *testing.T) {
	f := newAgentFixture(t)
	if code, _ := f.get(t, f.operator, "/api/v1/hosts"); code != http.StatusOK {
		t.Errorf("an operator reads: %d", code)
	}
	// An operator token cannot send results, and a read token cannot stand in for an operator.
	if code, _ := post(t, f.srv, f.operator, fixture(t, "db-01.json")); code != http.StatusUnauthorized {
		t.Errorf("an operator ingests: %d", code)
	}
	if _, err := f.store.Authenticate(context.Background(), f.api, ScopeOperator); err == nil {
		t.Error("a read token authenticated as an operator")
	}
}
