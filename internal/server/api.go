package server

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/with-developer/vmsctl/internal/engine"
	"github.com/with-developer/vmsctl/internal/output"
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
			w.Header().Set("WWW-Authenticate", `Bearer realm="vmsctl"`)
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
	mux.HandleFunc("GET /api/v1/profiles", s.readAPI(s.handleProfiles))
	mux.HandleFunc("GET /api/v1/overview", s.readAPI(s.handleOverview))
	mux.HandleFunc("GET /api/v1/trend", s.readAPI(s.handleTrend))
	mux.HandleFunc("GET /api/v1/hosts", s.readAPI(s.handleHosts))
	mux.HandleFunc("GET /api/v1/matrix", s.readAPI(s.handleMatrix))
	mux.HandleFunc("GET /api/v1/controls", s.readAPI(s.handleControls))
	mux.HandleFunc("GET /api/v1/controls/{profile}/{id}", s.readAPI(s.handleControl))
	mux.HandleFunc("GET /api/v1/hosts/{id}", s.readAPI(s.handleHost))
	mux.HandleFunc("GET /api/v1/hosts/{id}/agent", s.readAPI(s.handleHostAgent))
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

var profileParamRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

// selectedProfile reads ?profile=: the profile the numbers of a page are of. Without it, the profile that most
// hosts scanned with (hosts that scanned with several profiles would be counted twice otherwise, ADR 0010).
func (s *Server) selectedProfile(r *http.Request) (string, error) {
	if v := r.URL.Query().Get("profile"); v != "" {
		if v == "all" {
			return "", nil // every profile added up: what the dashboard counted before there were several
		}
		if !profileParamRe.MatchString(v) {
			return "", errors.New("profile is a profile ID")
		}
		return v, nil
	}
	uses, err := s.cfg.Store.Profiles(r.Context())
	if err != nil || len(uses) == 0 {
		return "", err
	}
	return uses[0].ID, nil
}

// handleProfiles lists the profiles of the latest scans with the number of hosts, and the one the pages show without
// a choice.
func (s *Server) handleProfiles(w http.ResponseWriter, r *http.Request) {
	uses, err := s.cfg.Store.Profiles(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	def := ""
	if len(uses) > 0 {
		def = uses[0].ID
	}
	titles := map[string]string{}
	if s.cfg.Content != nil {
		for _, u := range uses {
			if p := s.cfg.Content.Profiles[u.ID]; p != nil {
				titles[u.ID] = p.Title
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"profiles": uses, "default": def, "titles": titles})
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
	profile, err := s.selectedProfile(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	o, err := s.cfg.Store.Overview(r.Context(), after, profile)
	if err != nil {
		s.fail(w, err)
		return
	}
	for i := range o.TopFailing {
		o.TopFailing[i].TitleKo = s.titleKo(o.TopFailing[i].Profile, o.TopFailing[i].ID)
	}
	for i := range o.RecentRegression {
		o.RecentRegression[i].TitleKo = s.titleKo(o.RecentRegression[i].Profile, o.RecentRegression[i].ControlID)
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
	profile, err := s.selectedProfile(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	f := HostFilter{Query: q.Get("q"), Status: q.Get("status"), StaleAfter: after, Sort: q.Get("sort"), Profile: profile, Kind: q.Get("kind")}
	if f.Label = q.Get("label"); f.Label != "" {
		// the sizes a result may carry, in bytes as the store counts them (a key has no "=": it would not split)
		if k, v, ok := strings.Cut(f.Label, "="); !ok || k == "" || len(k) > maxLabelKey || len(v) > maxLabelValue {
			writeError(w, http.StatusBadRequest, `label is "key=value"`)
			return
		}
	}
	if f.Kind != "" && f.Kind != kindHost && f.Kind != kindImage {
		writeError(w, http.StatusBadRequest, `kind is "host" or "image"`)
		return
	}
	if f.Sort != "" && f.Sort != "name" && f.Sort != "score" && f.Sort != "last" && f.Sort != "recent" {
		writeError(w, http.StatusBadRequest, `sort is "name", "score", "last" or "recent"`)
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
	_ = cw.Write([]string{"host", "host_id", "last_scan", "stale", "score", "FAIL", "ERROR", "MANUAL", "WAIVED", "PASS", "NOT_APPLICABLE", "profile", "other_profile"})
	for _, h := range hosts {
		score := ""
		if h.Score != nil {
			score = strconv.FormatFloat(*h.Score, 'f', 3, 64)
		}
		row := []string{csvText(h.Name), csvText(h.HostID), h.LastScanAt, strconv.FormatBool(h.Stale), score}
		for _, st := range statusOrder {
			row = append(row, strconv.Itoa(h.Counts[st]))
		}
		row = append(row, csvText(h.Profile), strconv.FormatBool(h.OtherProfile))
		_ = cw.Write(row)
	}
	cw.Flush()
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="vmsctl-hosts.csv"`)
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
	profile, err := s.selectedProfile(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	d, err := s.cfg.Store.Host(r.Context(), id, after, profile)
	switch {
	case errors.Is(err, ErrNotFound):
		writeError(w, http.StatusNotFound, "no such host")
	case err != nil:
		s.fail(w, err)
	default:
		for i := range d.Controls {
			d.Controls[i].TitleKo = s.titleKo(d.Controls[i].Profile, d.Controls[i].ID)
		}
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
	format := r.URL.Query().Get("format")
	if format != "" && format != "csv" {
		writeError(w, http.StatusBadRequest, "format is csv, or leave it out for the JSON result")
		return
	}
	doc, err := s.cfg.Store.ScanDoc(r.Context(), id)
	switch {
	case errors.Is(err, ErrNotFound):
		writeError(w, http.StatusNotFound, "no such scan")
		return
	case err != nil:
		s.fail(w, err)
		return
	}
	if format == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(doc)
		return
	}
	// The CSV report of `vmsctl scan --format csv`, from the stored result, as a download for a spreadsheet.
	res, err := output.ReadResult(bytes.NewReader(doc))
	if err != nil {
		s.fail(w, fmt.Errorf("stored scan %d: %w", id, err))
		return
	}
	for i := range res.Controls { // the Korean titles the dashboard shows for a result that came without them
		if res.Controls[i].TitleKo == "" {
			res.Controls[i].TitleKo = s.titleKo(res.Controls[i].Profile, res.Controls[i].ID)
		}
	}
	var buf bytes.Buffer
	if err := output.Write(&buf, res, "csv", output.Options{}); err != nil {
		s.fail(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, csvFileName(res, id)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(buf.Bytes())
}

// csvFileName names the download after the host and the day of the scan, so files of several scans tell themselves apart:
// vmsctl-web-01-2026-11-11-scan-15.csv. The host name is the host's own text: only letters, digits, dot, dash and underscore stay.
func csvFileName(res *engine.Result, id int64) string {
	var host strings.Builder
	for _, r := range res.Host.Hostname {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			host.WriteRune(r)
		default:
			host.WriteByte('-')
		}
		if host.Len() >= 60 {
			break
		}
	}
	name := "vmsctl"
	if host.Len() > 0 {
		name += "-" + strings.Trim(host.String(), ".-")
	}
	if len(res.Scan.StartedAt) >= 10 {
		name += "-" + res.Scan.StartedAt[:10]
	}
	return fmt.Sprintf("%s-scan-%d.csv", name, id)
}

// handleDiff compares two stored scans with the code of `vmsctl diff`.
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
func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	cred, err := s.readCredential(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "a valid read token or session is required")
		return
	}
	// canScan tells the dashboard whether to offer "scan now": only an operator may ask for one.
	writeJSON(w, http.StatusOK, map[string]bool{"authenticated": true, "canScan": cred.Scope == ScopeOperator})
}

func (s *Server) handleMatrix(w http.ResponseWriter, r *http.Request) {
	after, err := staleAfter(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	profile, err := s.selectedProfile(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	m, err := s.cfg.Store.Matrix(r.Context(), after, profile)
	if err != nil {
		s.fail(w, err)
		return
	}
	for i := range m.Controls {
		m.Controls[i].TitleKo = s.titleKo(m.Controls[i].Profile, m.Controls[i].ID)
	}
	writeJSON(w, http.StatusOK, m)
}

func (s *Server) handleControls(w http.ResponseWriter, r *http.Request) {
	profile, err := s.selectedProfile(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	list, err := s.cfg.Store.Controls(r.Context(), profile)
	if err != nil {
		s.fail(w, err)
		return
	}
	for i := range list {
		list[i].TitleKo = s.titleKo(list[i].Profile, list[i].ID)
	}
	writeJSON(w, http.StatusOK, map[string]any{"controls": list})
}

// CheckInfo is what a check looks at and how to fix it: our own rule text.
type CheckInfo struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	TitleKo     string `json:"titleKo,omitempty"`
	Description string `json:"description"`
	Rationale   string `json:"rationale"`
	Remediation string `json:"remediation"`
	// The same in Korean, where the rule has it (the dashboard shows it when its language is Korean).
	DescriptionKo string `json:"descriptionKo,omitempty"`
	RationaleKo   string `json:"rationaleKo,omitempty"`
	RemediationKo string `json:"remediationKo,omitempty"`
}

// ControlInfo is the profile's own description of a control, when the server has the profiles.
type ControlInfo struct {
	TitleKo  string      `json:"titleKo,omitempty"`
	Manual   string      `json:"manual,omitempty"`
	ManualKo string      `json:"manualKo,omitempty"`
	Checks   []CheckInfo `json:"checks"`
}

func (s *Server) controlInfo(profile, id string) *ControlInfo {
	if s.cfg.Content == nil {
		return nil
	}
	p := s.cfg.Content.Profiles[profile]
	if p == nil {
		return nil
	}
	for _, c := range p.Controls {
		if c.ID != id {
			continue
		}
		info := &ControlInfo{TitleKo: c.TitleKo, Manual: strings.TrimSpace(c.Manual), ManualKo: strings.TrimSpace(c.ManualKo), Checks: []CheckInfo{}}
		for _, ref := range c.Checks {
			if ch := s.cfg.Content.Checks[ref]; ch != nil {
				info.Checks = append(info.Checks, CheckInfo{
					ID: ch.ID, Title: ch.Title, TitleKo: ch.TitleKo,
					Description: strings.TrimSpace(ch.Description), Rationale: strings.TrimSpace(ch.Rationale), Remediation: strings.TrimSpace(ch.Remediation),
					DescriptionKo: strings.TrimSpace(ch.DescriptionKo), RationaleKo: strings.TrimSpace(ch.RationaleKo), RemediationKo: strings.TrimSpace(ch.RemediationKo),
				})
			}
		}
		return info
	}
	return nil
}

func (s *Server) handleControl(w http.ResponseWriter, r *http.Request) {
	after, err := staleAfter(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	profile, id := r.PathValue("profile"), r.PathValue("id")
	if len(profile) > 64 || len(id) > 64 {
		writeError(w, http.StatusBadRequest, "not a control")
		return
	}
	d, err := s.cfg.Store.Control(r.Context(), profile, id, after)
	switch {
	case errors.Is(err, ErrNotFound):
		writeError(w, http.StatusNotFound, "no such control, or no host has a result for it")
	case err != nil:
		s.fail(w, err)
	default:
		d.TitleKo = s.titleKo(profile, id)
		writeJSON(w, http.StatusOK, map[string]any{"control": d, "info": s.controlInfo(profile, id)})
	}
}

// titleKo is the Korean title of a control from the profiles the server has, or "".
func (s *Server) titleKo(profile, id string) string {
	if s.cfg.Content == nil {
		return ""
	}
	if p := s.cfg.Content.Profiles[profile]; p != nil {
		for _, c := range p.Controls {
			if c.ID == id {
				return c.TitleKo
			}
		}
	}
	return ""
}

// handleTrend is the fleet's pass rate over the last days, one point a day (?days=30, at most 90).
func (s *Server) handleTrend(w http.ResponseWriter, r *http.Request) {
	days := 30
	if v := r.URL.Query().Get("days"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > maxTrendDays {
			writeError(w, http.StatusBadRequest, "days is 1 to "+strconv.Itoa(maxTrendDays))
			return
		}
		days = n
	}
	profile, err := s.selectedProfile(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	points, err := s.trends.get(s.cfg.Now(), days, profile, func() ([]TrendPoint, error) { return s.cfg.Store.Trend(r.Context(), days, profile) })
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"points": points})
}

// trendTTL is how long a computed trend is served again: the overview asks for it on every load, and it moves one
// point a day.
const trendTTL = 30 * time.Second

// trendCache keeps the last trend of each (days, profile) for trendTTL.
type trendCache struct {
	mu sync.Mutex
	m  map[string]trendEntry
}

type trendEntry struct {
	at     time.Time
	points []TrendPoint
}

func (c *trendCache) get(now time.Time, days int, profile string, compute func() ([]TrendPoint, error)) ([]TrendPoint, error) {
	key := strconv.Itoa(days) + "|" + profile
	c.mu.Lock()
	if e, ok := c.m[key]; ok && now.Sub(e.at) < trendTTL && now.Sub(e.at) >= 0 {
		c.mu.Unlock()
		return e.points, nil
	}
	c.mu.Unlock()
	points, err := compute()
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil || len(c.m) > 64 { // days and profile are few; a flood of profile names does not grow it
		c.m = map[string]trendEntry{}
	}
	c.m[key] = trendEntry{at: now, points: points}
	return points, nil
}
