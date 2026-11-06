package server

import (
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/with-developer/hostlint/internal/output"
)

// apiHandler is a read handler that runs for a request with a valid read token.
type apiHandler func(w http.ResponseWriter, r *http.Request)

// readAPI wraps a handler with the checks of the read API: an address limit, a valid api token
// and a per-token limit. Nothing is written to the database for a refused request.
func (s *Server) readAPI(next apiHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		remote := remoteAddr(r)
		if !s.limiter.allow("ip:"+remote, s.cfg.Rate*10) {
			w.Header().Set("Retry-After", "60")
			writeError(w, http.StatusTooManyRequests, "too many requests from this address")
			return
		}
		cred, err := s.cfg.Store.Authenticate(r.Context(), bearer(r), ScopeAPI)
		if errors.Is(err, ErrUnauthorized) {
			s.cfg.Logger.Warn("request refused", "reason", "bad token", "remote", remote)
			w.Header().Set("WWW-Authenticate", `Bearer realm="hostlint"`)
			writeError(w, http.StatusUnauthorized, "a valid read token is required")
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

func (s *Server) routesRead(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/overview", s.readAPI(s.handleOverview))
	mux.HandleFunc("GET /api/v1/hosts", s.readAPI(s.handleHosts))
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
	f := HostFilter{Query: q.Get("q"), Status: q.Get("status"), StaleAfter: after}
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
	if format == "csv" {
		f.Limit, f.Offset = 500, 0
	}
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
	var results [2]*output.DiffInput
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
		results[i] = &output.DiffInput{Name: fmt.Sprintf("scan %d", id), Result: res}
	}
	writeJSON(w, http.StatusOK, output.DiffResults(results[0].Name, results[0].Result, results[1].Name, results[1].Result))
}
