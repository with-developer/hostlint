package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The agent of a host (ADR 0014) asks the server whether there is something to do, over one long poll, and
// there is one thing the server can say: scan now, with a profile that the agent's own configuration allows.
const (
	agentOnlineFor  = 2 * time.Minute  // an agent that polled this recently is online
	jobMinInterval  = time.Minute      // at most one request per host per minute
	jobExpiresAfter = 10 * time.Minute // a request nobody took, or a scan that never came
	lostClaimAfter  = 5 * time.Second
	defaultPollHold = 25 * time.Second // how long a poll waits for a job (a proxy cuts a request after a minute)
	// MaxAgentProfiles is how many profiles an agent may allow.
	MaxAgentProfiles = 8
	maxJobError      = 300
)

var (
	// ErrAgentOffline means no agent of the host has polled lately.
	ErrAgentOffline = errors.New("no agent of this host is connected")
	// ErrProfileNotAllowed means the agent does not allow the profile.
	ErrProfileNotAllowed = errors.New("the agent does not allow that profile")
	// ErrTooSoon means a scan was requested for the host less than a minute ago, or one is pending.
	ErrTooSoon = errors.New("a scan of this host was requested a moment ago, or is still pending")

	agentProfileRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
)

// ValidAgentProfile reports whether s is shaped like a profile ID an agent may allow or a scan may ask for.
func ValidAgentProfile(s string) bool { return agentProfileRe.MatchString(s) }

// Job is a request for a scan.
type Job struct {
	ID         int64  `json:"id"`
	Profile    string `json:"profile"`
	State      string `json:"state"` // queued, claimed, done, failed, expired
	CreatedAt  string `json:"createdAt"`
	FinishedAt string `json:"finishedAt,omitempty"`
	Scan       int64  `json:"scan,omitempty"`
	Error      string `json:"error,omitempty"`
}

// AgentInfo is what the dashboard knows of a host's agent.
type AgentInfo struct {
	Online   bool     `json:"online"`
	Profiles []string `json:"profiles"`
	Job      *Job     `json:"job,omitempty"` // the latest request
}

// jobWaiters wake a poll when a job is queued for its host.
type jobWaiters struct {
	mu sync.Mutex
	ch map[int64]chan struct{}
}

func (w *jobWaiters) wait(host int64) chan struct{} {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.ch == nil {
		w.ch = map[int64]chan struct{}{}
	}
	c, ok := w.ch[host]
	if !ok {
		c = make(chan struct{})
		w.ch[host] = c
	}
	return c
}

func (w *jobWaiters) wake(host int64) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if c, ok := w.ch[host]; ok {
		close(c)
		delete(w.ch, host)
	}
}

func cleanProfiles(in []string) ([]string, bool) {
	var out []string
	for _, p := range in {
		if !agentProfileRe.MatchString(p) {
			return nil, false
		}
		if !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	return out, len(out) > 0 && len(out) <= MaxAgentProfiles
}

// AgentHost returns the row of the host a token is bound to: an agent's token is bound to a host that has sent a
// result, with the host ID the token is pinned to.
func (s *Store) AgentHost(ctx context.Context, cred *Credential) (int64, error) {
	if cred.BoundName == "" || strings.HasSuffix(cred.BoundName, "*") {
		return 0, fmt.Errorf("%w: an agent's token is bound to one host (server token create --host NAME)", ErrIdentity)
	}
	var row int64
	var hostID string
	err := s.db.QueryRowContext(ctx, `SELECT id, host_id FROM hosts WHERE name = ?`, cred.BoundName).Scan(&row, &hostID)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
	if err != nil {
		return 0, err
	}
	if cred.BoundHostID != "" && cred.BoundHostID != hostID {
		return 0, fmt.Errorf("%w: this token is pinned to another host ID", ErrIdentity)
	}
	return row, nil
}

// AgentSeen records that the agent of the host an ingest token is bound to polled, with the profiles it allows. It
// returns the host's row.
func (s *Store) AgentSeen(ctx context.Context, cred *Credential, profiles []string) (int64, error) {
	row, err := s.AgentHost(ctx, cred)
	if err != nil {
		return 0, err
	}
	_, err = s.db.ExecContext(ctx, `UPDATE hosts SET agent_seen_at = ?, agent_profiles = ? WHERE id = ?`, s.stamp(), strings.Join(profiles, " "), row)
	return row, err
}

// ClaimJob hands the host's agent the oldest request, if there is one. Requests that waited too long are expired.
func (s *Store) ClaimJob(ctx context.Context, hostRow int64) (*Job, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	cutoff := s.now().UTC().Add(-jobExpiresAfter).Format(stampLayout)
	// An agent polls one request at a time: a job that is still claimed when it asks again was lost on the way to it
	// (the answer never arrived), and is failed rather than left to block the host for ten minutes. The few seconds
	// are for a poll the agent gave up on whose answer was still being written.
	lost := s.now().UTC().Add(-lostClaimAfter).Format(stampLayout)
	if _, err := tx.ExecContext(ctx, `UPDATE agent_jobs SET state = 'failed', finished_at = ?, error = 'the agent never took the job' WHERE host_row = ? AND state = 'claimed' AND claimed_at < ?`, s.stamp(), hostRow, lost); err != nil {
		return nil, err
	}
	// A request is open for ten minutes from when it was made, and a claimed one from when it was taken.
	if _, err := tx.ExecContext(ctx, `UPDATE agent_jobs SET state = 'expired', finished_at = ? WHERE host_row = ? AND state IN ('queued', 'claimed') AND COALESCE(claimed_at, created_at) < ?`, s.stamp(), hostRow, cutoff); err != nil {
		return nil, err
	}
	var j Job
	err = tx.QueryRowContext(ctx, `SELECT id, profile, created_at FROM agent_jobs WHERE host_row = ? AND state = 'queued' ORDER BY id LIMIT 1`, hostRow).Scan(&j.ID, &j.Profile, &j.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, tx.Commit()
	}
	if err != nil {
		return nil, err
	}
	j.State = "claimed"
	if _, err := tx.ExecContext(ctx, `UPDATE agent_jobs SET state = 'claimed', claimed_at = ? WHERE id = ?`, s.stamp(), j.ID); err != nil {
		return nil, err
	}
	return &j, tx.Commit()
}

// CreateJob asks the agent of a host for a scan with a profile. The host's agent has to be online and to allow the
// profile, and a host is asked once a minute at most; the request is audited with who made it.
func (s *Store) CreateJob(ctx context.Context, cred *Credential, remote string, hostRow int64, profile string) (*Job, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	var name string
	var seen sql.NullString
	var allowed string
	err = tx.QueryRowContext(ctx, `SELECT name, agent_seen_at, agent_profiles FROM hosts WHERE id = ?`, hostRow).Scan(&name, &seen, &allowed)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	now := s.now().UTC()
	if !agentOnline(seen.String, now) {
		return nil, ErrAgentOffline
	}
	if !slices.Contains(strings.Fields(allowed), profile) {
		return nil, ErrProfileNotAllowed
	}
	var recent int
	cutoff := now.Add(-jobMinInterval).Format(stampLayout)
	pending := now.Add(-jobExpiresAfter).Format(stampLayout)
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM agent_jobs WHERE host_row = ? AND (created_at >= ? OR (state IN ('queued', 'claimed') AND COALESCE(claimed_at, created_at) >= ?))`, hostRow, cutoff, pending).Scan(&recent); err != nil {
		return nil, err
	}
	if recent > 0 {
		return nil, ErrTooSoon
	}
	at := s.stamp()
	r, err := tx.ExecContext(ctx, `INSERT INTO agent_jobs (host_row, profile, requested_by, created_at, state) VALUES (?, ?, ?, ?, 'queued')`, hostRow, profile, cred.ID, at)
	if err != nil {
		return nil, err
	}
	id, err := r.LastInsertId()
	if err != nil {
		return nil, err
	}
	if err := appendAudit(ctx, tx, at, cred.ID, remote, "scan-requested", fmt.Sprintf("host %s, profile %s, job %d", name, profile, id)); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &Job{ID: id, Profile: profile, State: "queued", CreatedAt: at}, nil
}

// FinishJob marks a claimed job of the host done, with the scan that answered it. A job that is not the host's,
// or not claimed, is left alone: what a result says about its job is a hint, never a way to touch another's.
func (s *Store) FinishJob(ctx context.Context, jobID, hostRow, scanRow int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE agent_jobs SET state = 'done', finished_at = ?, scan_row = ? WHERE id = ? AND host_row = ? AND state = 'claimed'`, s.stamp(), scanRow, jobID, hostRow)
	return err
}

// FailJob records that the agent could not do a claimed job.
func (s *Store) FailJob(ctx context.Context, jobID, hostRow int64, msg string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE agent_jobs SET state = 'failed', finished_at = ?, error = ? WHERE id = ? AND host_row = ? AND state = 'claimed'`, s.stamp(), truncate(msg, maxJobError), jobID, hostRow)
	return err
}

// HostAgent is what the dashboard shows of a host's agent.
func (s *Store) HostAgent(ctx context.Context, hostRow int64) (*AgentInfo, error) {
	var seen sql.NullString
	var allowed string
	err := s.db.QueryRowContext(ctx, `SELECT agent_seen_at, agent_profiles FROM hosts WHERE id = ?`, hostRow).Scan(&seen, &allowed)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	a := &AgentInfo{Profiles: strings.Fields(allowed)}
	if a.Profiles == nil {
		a.Profiles = []string{}
	}
	if agentOnline(seen.String, s.now().UTC()) {
		a.Online = true
	}
	var j Job
	var finished sql.NullString
	var scan sql.NullInt64
	var claimed sql.NullString
	err = s.db.QueryRowContext(ctx, `SELECT id, profile, state, created_at, claimed_at, finished_at, scan_row, error FROM agent_jobs WHERE host_row = ? ORDER BY id DESC LIMIT 1`, hostRow).
		Scan(&j.ID, &j.Profile, &j.State, &j.CreatedAt, &claimed, &finished, &scan, &j.Error)
	switch {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return nil, err
	default:
		j.FinishedAt, j.Scan = finished.String, scan.Int64
		// A request that waited too long reads as expired, whether or not a poll has noticed. An agent that is
		// scanning does not poll: a job it took is a sign of life until it expires.
		last := j.CreatedAt
		if claimed.Valid {
			last = claimed.String
		}
		if t, err := time.Parse(stampLayout, last); err == nil && (j.State == "queued" || j.State == "claimed") {
			if s.now().UTC().Sub(t) > jobExpiresAfter {
				j.State = "expired"
			} else if j.State == "claimed" {
				a.Online = true
			}
		}
		a.Job = &j
	}
	return a, nil
}

// handleAgentPoll is the agent's long poll: it says which profiles the agent allows and waits for a job.
func (s *Server) handleAgentPoll(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	remote := s.remote(r)
	// Polls have a budget of their own: a fleet behind one address must not use up the one of its results.
	if !s.limiter.allow("pip:"+remote, s.cfg.Rate*10) {
		w.Header().Set("Retry-After", "60")
		writeError(w, http.StatusTooManyRequests, "too many requests from this address")
		return
	}
	cred, err := s.cfg.Store.Authenticate(ctx, bearer(r), ScopeIngest)
	if errors.Is(err, ErrUnauthorized) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="hostlint"`)
		writeError(w, http.StatusUnauthorized, "a valid ingest token is required")
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	// A poll is held for 25 seconds, so a healthy agent asks about three times a minute.
	if !s.limiter.allow(fmt.Sprintf("poll:%d", cred.ID), 12) {
		w.Header().Set("Retry-After", "60")
		writeError(w, http.StatusTooManyRequests, "polling too often")
		return
	}
	if !jsonRequest(r) {
		writeError(w, http.StatusUnsupportedMediaType, "send application/json")
		return
	}
	var body struct {
		Allow []string `json:"allow"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, `send {"allow": ["profile-id"]}`)
		return
	}
	profiles, ok := cleanProfiles(body.Allow)
	if !ok {
		writeError(w, http.StatusBadRequest, "allow is one to eight profile IDs")
		return
	}
	row, err := s.cfg.Store.AgentSeen(ctx, cred, profiles)
	switch {
	case errors.Is(err, ErrNotFound):
		writeError(w, http.StatusConflict, "this host has not sent a result yet: scan once with --push, then start the agent")
		return
	case errors.Is(err, ErrIdentity):
		writeError(w, http.StatusConflict, err.Error())
		return
	case err != nil:
		s.fail(w, err)
		return
	}
	hold := s.cfg.PollHold
	if hold == 0 {
		hold = defaultPollHold
	}
	// The server's write timeout is shorter than a poll.
	_ = http.NewResponseController(w).SetWriteDeadline(s.cfg.Now().Add(hold + 15*time.Second))
	deadline := time.NewTimer(hold)
	defer deadline.Stop()
	for {
		wake := s.jobs.wait(row) // taken before the check, so a job queued in between is not missed
		job, err := s.cfg.Store.ClaimJob(ctx, row)
		if err != nil {
			s.fail(w, err)
			return
		}
		if job != nil {
			writeJSON(w, http.StatusOK, map[string]any{"job": job})
			return
		}
		select {
		case <-wake:
		case <-deadline.C:
			w.WriteHeader(http.StatusNoContent)
			return
		case <-ctx.Done():
			return
		}
	}
}

// handleJobFail records that the agent could not do its job.
func (s *Server) handleJobFail(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !s.limiter.allow("pip:"+s.remote(r), s.cfg.Rate*10) {
		w.Header().Set("Retry-After", "60")
		writeError(w, http.StatusTooManyRequests, "too many requests from this address")
		return
	}
	cred, err := s.cfg.Store.Authenticate(ctx, bearer(r), ScopeIngest)
	if errors.Is(err, ErrUnauthorized) {
		writeError(w, http.StatusUnauthorized, "a valid ingest token is required")
		return
	}
	if err != nil || cred.BoundName == "" {
		writeError(w, http.StatusUnauthorized, "a valid ingest token bound to a host is required")
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id < 1 || !jsonRequest(r) {
		writeError(w, http.StatusBadRequest, "send application/json to /api/v1/agent/jobs/{id}/fail")
		return
	}
	var body struct {
		Error string `json:"error"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2048)).Decode(&body); err != nil || !printable(body.Error) {
		writeError(w, http.StatusBadRequest, `send {"error": "text"}`)
		return
	}
	row, err := s.cfg.Store.AgentHost(ctx, cred)
	if err != nil {
		writeError(w, http.StatusConflict, "this token is not an agent's: "+err.Error())
		return
	}
	if err := s.cfg.Store.FailJob(ctx, id, row, body.Error); err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// writeCredential is the credential of a request that changes something: an operator token, or the session of
// an operator when the request is one a page of this site could have made and a page of another site could not
// (JSON, and an Origin that is this site's: cookies are SameSite=Strict as well).
func (s *Server) writeCredential(r *http.Request) (*Credential, error) {
	if tok := bearer(r); tok != "" {
		cred, err := s.cfg.Store.Authenticate(r.Context(), tok, ScopeOperator)
		if errors.Is(err, ErrUnauthorized) {
			// A good read token is told it may not, a wrong one that it is unknown.
			if _, rerr := s.cfg.Store.Authenticate(r.Context(), tok, ScopeAPI); rerr == nil {
				return nil, ErrForbidden
			}
		}
		return cred, err
	}
	ck, err := r.Cookie(SessionCookie)
	if err != nil || !jsonRequest(r) || !sameOrigin(r) {
		return nil, ErrUnauthorized
	}
	cred, err := s.cfg.Store.AuthenticateSession(r.Context(), ck.Value)
	if err != nil {
		return nil, err
	}
	if cred.Scope != ScopeOperator {
		return nil, ErrForbidden
	}
	return cred, nil
}

// ErrForbidden means the credential is good but may not do this.
var ErrForbidden = errors.New("forbidden")

// sameOrigin reports whether the request carries an Origin that is the site it was sent to.
func sameOrigin(r *http.Request) bool {
	o := r.Header.Get("Origin")
	if o == "" {
		return false
	}
	i := strings.Index(o, "://")
	return i > 0 && o[i+3:] == r.Host
}

// handleScanRequest asks the agent of a host for a scan.
func (s *Server) handleScanRequest(w http.ResponseWriter, r *http.Request) {
	remote := s.remote(r)
	if !s.limiter.allow("rip:"+remote, s.cfg.Rate*10) {
		w.Header().Set("Retry-After", "60")
		writeError(w, http.StatusTooManyRequests, "too many requests from this address")
		return
	}
	cred, err := s.writeCredential(r)
	switch {
	case errors.Is(err, ErrUnauthorized):
		w.Header().Set("WWW-Authenticate", `Bearer realm="hostlint"`)
		writeError(w, http.StatusUnauthorized, "an operator token or the session of one is required")
		return
	case errors.Is(err, ErrForbidden):
		writeError(w, http.StatusForbidden, "this token may read, not ask for scans: use an operator token")
		return
	case err != nil:
		s.fail(w, err)
		return
	}
	id, ok := pathID(r)
	if !ok || !jsonRequest(r) {
		writeError(w, http.StatusBadRequest, "send application/json to /api/v1/hosts/{id}/scan")
		return
	}
	var body struct {
		Profile string `json:"profile"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&body); err != nil || !agentProfileRe.MatchString(body.Profile) {
		writeError(w, http.StatusBadRequest, `send {"profile": "profile-id"}`)
		return
	}
	job, err := s.cfg.Store.CreateJob(r.Context(), cred, remote, id, body.Profile)
	switch {
	case errors.Is(err, ErrNotFound):
		writeError(w, http.StatusNotFound, "no such host")
	case errors.Is(err, ErrAgentOffline), errors.Is(err, ErrProfileNotAllowed):
		writeError(w, http.StatusConflict, err.Error())
	case errors.Is(err, ErrTooSoon):
		w.Header().Set("Retry-After", "60")
		writeError(w, http.StatusTooManyRequests, err.Error())
	case err != nil:
		s.fail(w, err)
	default:
		s.jobs.wake(id)
		writeJSON(w, http.StatusAccepted, map[string]any{"job": job})
	}
}

// handleHostAgent tells the dashboard about the agent of a host: connected or not, what it allows, the latest request.
func (s *Server) handleHostAgent(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "not a host ID")
		return
	}
	a, err := s.cfg.Store.HostAgent(r.Context(), id)
	switch {
	case errors.Is(err, ErrNotFound):
		writeError(w, http.StatusNotFound, "no such host")
	case err != nil:
		s.fail(w, err)
	default:
		writeJSON(w, http.StatusOK, a)
	}
}

// agentOnline is the one rule for "connected": the agent polled within agentOnlineFor of now (seen is the stamp of its
// last poll, "" for an agent that never did).
func agentOnline(seen string, now time.Time) bool {
	t, err := time.Parse(stampLayout, seen)
	return err == nil && now.Sub(t) <= agentOnlineFor
}
