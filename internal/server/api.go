package server

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/with-developer/hostlint/internal/engine"
	"github.com/with-developer/hostlint/internal/output"
)

// apiHandler is a read handler that runs for a request with a valid read token.
type apiHandler func(w http.ResponseWriter, r *http.Request)

// readAPI wraps a handler with the checks of the read API: an address limit, a valid api token
// and a per-token limit. Nothing is written to the database for a refused request.
func (s *Server) readAPI(next apiHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		remote := s.remote(r)
		if !s.limiter.allow("rip:"+remote, s.cfg.Rate*10) {
			w.Header().Set("Retry-After", "60")
			writeError(w, http.StatusTooManyRequests, "too many requests from this address")
			return
		}
		cred, err := s.readCredential(r)
		if errors.Is(err, ErrUnauthorized) {
			s.cfg.Logger.Info("request refused", "reason", "no valid read credential", "remote", remote)
			w.Header().Set("WWW-Authenticate", `Bearer realm="hostlint"`)
			writeError(w, http.StatusUnauthorized, "a valid read token or session is required")
			return
		}
		if err != nil {
			s.fail(w, err)
			return
		}
		if !s.limiter.allow(fmt.Sprintf("api:%d", cred.ID), s.cfg.Rate*10) {
			w.Header().Set("Retry-After", "60")
			writeError(w, http.StatusTooManyRequests, "too many requests from this token")
			return
		}
		next(w, r)
	}
}

// readCredential authenticates a read request: a read token in the Authorization header, or
// the session cookie of the dashboard. A session is only ever used for GET.
func (s *Server) readCredential(r *http.Request) (*Credential, error) {
	if tok := bearer(r); tok != "" {
		return s.cfg.Store.Authenticate(r.Context(), tok, ScopeAPI)
	}
	if ck, err := r.Cookie(SessionCookie); err == nil && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
		return s.cfg.Store.AuthenticateSession(r.Context(), ck.Value)
	}
	return nil, ErrUnauthorized
}

func (s *Server) routesRead(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/login", s.handleLogin)
	mux.HandleFunc("POST /api/v1/logout", s.handleLogout)
	mux.HandleFunc("GET /api/v1/session", s.readAPI(s.handleSession))
	mux.HandleFunc("GET /api/v1/overview", s.readAPI(s.handleOverview))
	mux.HandleFunc("GET /api/v1/hosts", s.readAPI(s.handleHosts))
	mux.HandleFunc("GET /api/v1/matrix", s.readAPI(s.handleMatrix))
	mux.HandleFunc("GET /api/v1/hosts/{id}", s.readAPI(s.handleHost))
	mux.HandleFunc("GET /api/v1/scans/{id}", s.readAPI(s.handleScan))
	mux.HandleFunc("GET /api/v1/diff", s.readAPI(s.handleDiff))
}

// staleAfter reads ?staleDays= (1 to 365, 7 by default).
func staleAfter(r *http.Request) (time.Duration, error) {
	v := r.URL.Query().Get("staleDays")
	if v == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 || n > 365 {
		return 0, errors.New("staleDays is a number of days from 1 to 365")
	}
	return time.Duration(n) * 24 * time.Hour, nil
}

func pathID(r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	return id, err == nil && id > 0
}

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	after, err := staleAfter(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	o, err := s.cfg.Store.Overview(r.Context(), after)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, o)
}

func (s *Server) handleHosts(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	after, err := staleAfter(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	f := HostFilter{Query: q.Get("q"), Status: q.Get("status"), StaleAfter: after, Sort: q.Get("sort")}
	if f.Sort != "" && f.Sort != "name" && f.Sort != "score" && f.Sort != "last" {
		writeError(w, http.StatusBadRequest, `sort is "name", "score" or "last"`)
		return
	}
	if f.Status != "" && f.Status != "failing" && f.Status != "stale" {
		writeError(w, http.StatusBadRequest, `status is "failing" or "stale"`)
		return
	}
	for name, dst := range map[string]*int{"limit": &f.Limit, "offset": &f.Offset} {
		if v := q.Get(name); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 {
				writeError(w, http.StatusBadRequest, name+" is a number")
				return
			}
			*dst = n
		}
	}
	format := q.Get("format")
	f.All = format == "csv" // the export is every host that matches
	hosts, total, err := s.cfg.Store.Hosts(r.Context(), f)
	if err != nil {
		s.fail(w, err)
		return
	}
	if format == "csv" {
		writeHostsCSV(w, hosts)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"hosts": hosts, "total": total})
}

// writeHostsCSV exports the list. A cell that a spreadsheet would run as a formula is made text.
func writeHostsCSV(w http.ResponseWriter, hosts []HostSummary) {
	var b bytes.Buffer
	cw := csv.NewWriter(&b)
	_ = cw.Write([]string{"host", "host_id", "last_scan", "stale", "score", "FAIL", "ERROR", "MANUAL", "WAIVED", "PASS", "NOT_APPLICABLE"})
	for _, h := range hosts {
		score := ""
		if h.Score != nil {
			score = strconv.FormatFloat(*h.Score, 'f', 3, 64)
		}
		row := []string{csvText(h.Name), csvText(h.HostID), h.LastScanAt, strconv.FormatBool(h.Stale), score}
		for _, st := range statusOrder {
			row = append(row, strconv.Itoa(h.Counts[st]))
		}
		_ = cw.Write(row)
	}
	cw.Flush()
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="hostlint-hosts.csv"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b.Bytes())
}

func csvText(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

func (s *Server) handleHost(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "not a host ID")
		return
	}
	after, err := staleAfter(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	d, err := s.cfg.Store.Host(r.Context(), id, after)
	switch {
	case errors.Is(err, ErrNotFound):
		writeError(w, http.StatusNotFound, "no such host")
	case err != nil:
		s.fail(w, err)
	default:
		writeJSON(w, http.StatusOK, d)
	}
}

// handleScan returns a stored result exactly as it was received. It is data from a host: the
// reader must treat every string in it as text.
func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "not a scan ID")
		return
	}
	doc, err := s.cfg.Store.ScanDoc(r.Context(), id)
	switch {
	case errors.Is(err, ErrNotFound):
		writeError(w, http.StatusNotFound, "no such scan")
	case err != nil:
		s.fail(w, err)
	default:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(doc)
	}
}

// handleDiff compares two stored scans with the code of `hostlint diff`.
func (s *Server) handleDiff(w http.ResponseWriter, r *http.Request) {
	ids := [2]int64{}
	for i, name := range []string{"old", "new"} {
		n, err := strconv.ParseInt(r.URL.Query().Get(name), 10, 64)
		if err != nil || n < 1 {
			writeError(w, http.StatusBadRequest, "old and new are scan IDs")
			return
		}
		ids[i] = n
	}
	type scan struct {
		name   string
		result *engine.Result
	}
	var scans [2]scan
	for i, id := range ids {
		doc, err := s.cfg.Store.ScanDoc(r.Context(), id)
		if errors.Is(err, ErrNotFound) {
			writeError(w, http.StatusNotFound, fmt.Sprintf("no scan %d", id))
			return
		}
		if err != nil {
			s.fail(w, err)
			return
		}
		res, err := output.ReadResult(bytes.NewReader(doc))
		if err != nil {
			s.fail(w, fmt.Errorf("stored scan %d: %w", id, err))
			return
		}
		scans[i] = scan{fmt.Sprintf("scan %d", id), res}
	}
	writeJSON(w, http.StatusOK, output.DiffResults(scans[0].name, scans[0].result, scans[1].name, scans[1].result))
}

// secureCookie reports whether the session cookie gets the Secure attribute: when the
// connection is TLS, or a TLS proxy in front says so (only if the server was told to trust it).
func (s *Server) secureCookie(r *http.Request) bool {
	return r.TLS != nil || (s.cfg.BehindProxy && strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https"))
}

// jsonRequest requires a JSON content type: a browser cannot send one cross-site without a
// preflight, so a page on another site cannot log a user in or out.
func jsonRequest(r *http.Request) bool {
	ct, _, _ := strings.Cut(r.Header.Get("Content-Type"), ";")
	return strings.EqualFold(strings.TrimSpace(ct), "application/json")
}

// handleLogin exchanges a read token for a session cookie.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	remote := s.remote(r)
	if !jsonRequest(r) {
		writeError(w, http.StatusUnsupportedMediaType, "send application/json")
		return
	}
	if !s.limiter.allow("login:"+remote, 10) {
		w.Header().Set("Retry-After", "60")
		writeError(w, http.StatusTooManyRequests, "too many login attempts from this address")
		return
	}
	var body struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "send {\"token\": \"hlt_api_...\"}")
		return
	}
	cred, err := s.cfg.Store.Authenticate(r.Context(), strings.TrimSpace(body.Token), ScopeAPI)
	if errors.Is(err, ErrUnauthorized) {
		s.cfg.Logger.Warn("login refused", "remote", remote)
		writeError(w, http.StatusUnauthorized, "that is not a valid read token")
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	value, err := s.cfg.Store.CreateSession(r.Context(), cred.ID)
	if err != nil {
		s.fail(w, err)
		return
	}
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // Secure follows the connection: a loopback http server cannot set it
		Name: SessionCookie, Value: value, Path: "/", MaxAge: int(sessionAbsolute.Seconds()),
		HttpOnly: true, Secure: s.secureCookie(r), SameSite: http.SameSiteStrictMode,
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "name": cred.Name})
}

// handleLogout ends the session of the request's cookie.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if !jsonRequest(r) {
		writeError(w, http.StatusUnsupportedMediaType, "send application/json")
		return
	}
	if ck, err := r.Cookie(SessionCookie); err == nil {
		if err := s.cfg.Store.DeleteSession(r.Context(), ck.Value); err != nil {
			s.fail(w, err)
			return
		}
	}
	http.SetCookie(w, &http.Cookie{Name: SessionCookie, Value: "", Path: "/", MaxAge: -1, //nolint:gosec // Secure follows the connection, as at login
		HttpOnly: true, Secure: s.secureCookie(r), SameSite: http.SameSiteStrictMode})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// handleSession tells the dashboard whether its cookie is still good.
func (s *Server) handleSession(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]bool{"authenticated": true})
}

func (s *Server) handleMatrix(w http.ResponseWriter, r *http.Request) {
	after, err := staleAfter(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	m, err := s.cfg.Store.Matrix(r.Context(), after)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, m)
}
