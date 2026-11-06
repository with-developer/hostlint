package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/with-developer/hostlint/internal/engine"
	"github.com/with-developer/hostlint/internal/output"
)

// Limits on what a host may send (ADR 0010). A full scan of a stock host is about 125 KiB.
const (
	DefaultMaxBody = 2 << 20
	maxControls    = 500
	maxChecks      = 5000
	maxText        = 4096
	maxFuture      = 5 * time.Minute
	maxScanAge     = 400 * 24 * time.Hour
)

// Config configures a Server.
type Config struct {
	Store   *Store
	MaxBody int64 // bytes of one result; DefaultMaxBody when 0
	Logger  *slog.Logger
	// Rate is how many results one token may send per minute (60 when 0).
	Rate int
	Now  func() time.Time
}

// Server handles the HTTP API.
type Server struct {
	cfg     Config
	limiter *limiter
}

// New returns a Server.
func New(cfg Config) *Server {
	if cfg.MaxBody == 0 {
		cfg.MaxBody = DefaultMaxBody
	}
	if cfg.Rate == 0 {
		cfg.Rate = 60
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	} else {
		cfg.Store.now = cfg.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Server{cfg: cfg, limiter: newLimiter(cfg.Rate, cfg.Now)}
}

// Handler returns the HTTP handler of the API.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/results", s.handleIngest)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	return secure(mux)
}

// secure sets the headers every response carries. The API returns JSON only.
func secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Cache-Control", "no-store")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// bearer returns the token of an Authorization: Bearer header.
func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

func remoteAddr(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) handleIngest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	remote := remoteAddr(r)
	cred, err := s.cfg.Store.Authenticate(ctx, bearer(r), ScopeIngest)
	if errors.Is(err, ErrUnauthorized) {
		s.reject(ctx, 0, remote, "bad token", "")
		w.Header().Set("WWW-Authenticate", `Bearer realm="hostlint"`)
		writeError(w, http.StatusUnauthorized, "a valid ingest token is required")
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	if !s.limiter.allow(cred.ID) {
		s.reject(ctx, cred.ID, remote, "rate limit", "")
		w.Header().Set("Retry-After", "60")
		writeError(w, http.StatusTooManyRequests, "too many results from this token")
		return
	}

	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, s.cfg.MaxBody))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			s.reject(ctx, cred.ID, remote, "too large", fmt.Sprintf("more than %d bytes", s.cfg.MaxBody))
			writeError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("a result may not exceed %d bytes", s.cfg.MaxBody))
			return
		}
		writeError(w, http.StatusBadRequest, "the request body could not be read")
		return
	}
	res, err := output.ReadResult(bytes.NewReader(raw))
	if err == nil {
		err = checkLimits(res, s.cfg.Now())
	}
	if err != nil {
		s.reject(ctx, cred.ID, remote, "invalid result", err.Error())
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}

	got, err := s.cfg.Store.IngestScan(ctx, cred, res, raw, remote)
	switch {
	case errors.Is(err, ErrDuplicate):
		s.reject(ctx, cred.ID, remote, "duplicate", res.Scan.ID)
		writeError(w, http.StatusConflict, err.Error())
	case errors.Is(err, ErrIdentity):
		s.reject(ctx, cred.ID, remote, "identity", err.Error())
		writeError(w, http.StatusConflict, err.Error())
	case err != nil:
		s.fail(w, err)
	default:
		writeJSON(w, http.StatusCreated, map[string]any{
			"scan": got.ScanRow, "host": got.HostRow, "receivedAt": got.ReceivedAt, "digest": got.Digest,
		})
	}
}

// reject records a refused request in the audit table and the log.
func (s *Server) reject(ctx context.Context, credID int64, remote, action, detail string) {
	s.cfg.Logger.Warn("result refused", "reason", action, "remote", remote, "credential", credID)
	if err := s.cfg.Store.Audit(context.WithoutCancel(ctx), credID, remote, "reject: "+action, detail); err != nil {
		s.cfg.Logger.Error("audit", "error", err)
	}
}

func (s *Server) fail(w http.ResponseWriter, err error) {
	s.cfg.Logger.Error("request failed", "error", err)
	writeError(w, http.StatusInternalServerError, "the server could not store the result")
}

// checkLimits bounds a result that passed ReadResult, which only checks that it is well formed.
func checkLimits(res *engine.Result, now time.Time) error {
	switch {
	case len(res.Controls) > maxControls:
		return fmt.Errorf("more than %d controls", maxControls)
	case len(res.Checks) > maxChecks:
		return fmt.Errorf("more than %d checks", maxChecks)
	case len(res.Host.Hostname) > 253 || len(res.Host.HostID) > 128 || len(res.Scan.ID) > 128 || len(res.Scan.Tool.Version) > 128:
		return errors.New("a host or scan identifier is too long")
	case res.Scan.ID == "":
		return errors.New("the result has no scan ID")
	}
	for _, c := range res.Controls {
		if len(c.ID) > 64 || len(c.Profile) > 64 || len(c.Title) > maxText || len(c.Reason) > maxText {
			return fmt.Errorf("control %.40q has text that is too long", c.ID)
		}
	}
	for _, c := range res.Checks {
		if len(c.Ref) > 256 || len(c.Title) > maxText || len(c.Reason) > maxText {
			return fmt.Errorf("check %.40q has text that is too long", c.Ref)
		}
	}
	// The server orders scans by its own clock; a start time far from it is not believed.
	started, err := time.Parse(time.RFC3339, res.Scan.StartedAt)
	if err != nil {
		return errors.New("scan.startedAt is not a timestamp")
	}
	switch {
	case started.After(now.Add(maxFuture)):
		return errors.New("scan.startedAt is in the future")
	case started.Before(now.Add(-maxScanAge)):
		return errors.New("scan.startedAt is older than the server keeps")
	}
	return nil
}

// limiter is a token bucket per credential.
type limiter struct {
	mu      sync.Mutex
	per     int
	now     func() time.Time
	buckets map[int64]*bucket
}

type bucket struct {
	tokens float64
	at     time.Time
}

func newLimiter(perMinute int, now func() time.Time) *limiter {
	return &limiter{per: perMinute, now: now, buckets: map[int64]*bucket{}}
}

func (l *limiter) allow(id int64) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b, ok := l.buckets[id]
	if !ok {
		b = &bucket{tokens: float64(l.per), at: now}
		l.buckets[id] = b
	}
	b.tokens = min(float64(l.per), b.tokens+now.Sub(b.at).Minutes()*float64(l.per))
	b.at = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
