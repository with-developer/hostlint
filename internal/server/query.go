package server

import (
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/with-developer/hostlint/internal/signing"
)

// ErrNotFound means there is no such host or scan.
var ErrNotFound = errors.New("not found")

// Statuses in the order the dashboard shows them.
var statusOrder = []string{"FAIL", "ERROR", "MANUAL", "WAIVED", "PASS", "NOT_APPLICABLE"}

// Counts is how many controls have each status.
type Counts map[string]int

// Score is PASS ÷ (PASS + FAIL + ERROR + MANUAL) (ADR 0010): results that are not decided count
// against it, and NOT_APPLICABLE and WAIVED are left out of the ratio and shown beside it.
// It is nil when nothing was decided.
func (c Counts) Score() *float64 {
	den := c["PASS"] + c["FAIL"] + c["ERROR"] + c["MANUAL"]
	if den == 0 {
		return nil
	}
	v := float64(c["PASS"]) / float64(den)
	return &v
}

// HostSummary is one host as the list shows it: its latest scan, counted.
type HostSummary struct {
	ID         int64    `json:"id"`
	Name       string   `json:"name"`
	HostID     string   `json:"hostId"`
	LastScanAt string   `json:"lastScanAt"`
	LatestScan int64    `json:"latestScan"`
	Counts     Counts   `json:"counts"`
	Score      *float64 `json:"score"`
	Stale      bool     `json:"stale"`
	// Profile is the profile the counts are of ("" counts every profile of the scan); OtherProfile is true for a
	// host whose latest scan has no control of it, so it has no counts here.
	Profile      string `json:"profile"`
	OtherProfile bool   `json:"otherProfile"`
	// Signed is true when the host signs its results; KeyFingerprint names the key it registered.
	Signed         bool   `json:"signed"`
	KeyFingerprint string `json:"keyFingerprint,omitempty"`
	// OS and Labels are what the host's latest result says of itself (bounded text, ADR 0010 limits).
	OS     string            `json:"os,omitempty"`
	Labels map[string]string `json:"labels,omitempty"`
	// AgentOnline is true when the host's agent polled lately (ADR 0014).
	AgentOnline bool `json:"agentOnline"`
	// Trend is the pass rate of the host's latest scans, oldest first (at most trendScans); scans with nothing
	// decided are left out. It is set for the hosts of a list page, not for the export.
	Trend []float64 `json:"trend,omitempty"`
}

// trendScans is how many scans a host's trend has.
const trendScans = 14

// HostFilter selects and pages the host list.
type HostFilter struct {
	Query      string        // part of the host name
	Status     string        // "failing" (a FAIL control), "stale", or "" for all
	StaleAfter time.Duration // a host that has not reported for this long is stale (7 days when 0)
	Limit      int           // 100 when 0, at most 500
	Offset     int
	Profile    string // count the controls of this profile only ("" counts all of them)
	All        bool   // every match: no paging (the export)
	Sort       string // "name" (default), "score" (worst first, undecided last) or "last" (longest silent first)
}

const latestScans = `SELECT id, host_row FROM scans s WHERE id = (SELECT id FROM scans WHERE host_row = s.host_row ORDER BY received_at DESC, id DESC LIMIT 1)`

// allHosts returns every host whose name contains query (and the host with id, when id is not
// 0) with the counts of its latest scan, sorted by name.
func (s *Store) allHosts(ctx context.Context, query string, id int64, staleAfter time.Duration, profile string) ([]HostSummary, error) {
	if staleAfter == 0 {
		staleAfter = 7 * 24 * time.Hour
	}
	rs, err := s.db.QueryContext(ctx, `
		SELECT h.id, h.name, h.host_id, COALESCE(h.last_scan_at, ''), COALESCE(l.id, 0), h.pubkey, h.os, h.labels, COALESCE(h.agent_seen_at, '')
		FROM hosts h LEFT JOIN (`+latestScans+`) l ON l.host_row = h.id
		WHERE h.name LIKE ? ESCAPE '\' AND (? = 0 OR h.id = ?)
		ORDER BY h.name, h.id`, "%"+likeEscape(query)+"%", id, id)
	if err != nil {
		return nil, err
	}
	var all []HostSummary
	for rs.Next() {
		var h HostSummary
		var key, labels, seen string
		if err := rs.Scan(&h.ID, &h.Name, &h.HostID, &h.LastScanAt, &h.LatestScan, &key, &h.OS, &labels, &seen); err != nil {
			_ = rs.Close()
			return nil, err
		}
		h.Signed, h.KeyFingerprint = key != "", signing.Fingerprint(key)
		if labels != "" {
			_ = json.Unmarshal([]byte(labels), &h.Labels) // written by hostInfo: bounded
		}
		if t, err := time.Parse(stampLayout, seen); err == nil && s.now().UTC().Sub(t) <= agentOnlineFor {
			h.AgentOnline = true
		}
		all = append(all, h)
	}
	if err := rs.Err(); err != nil {
		return nil, err
	}
	_ = rs.Close()
	counts, err := s.countsOfLatestScans(ctx, id, profile)
	if err != nil {
		return nil, err
	}
	var scored map[int64]Counts // every profile: told apart a scan of another profile from a scan with no controls
	if profile != "" {
		if scored, err = s.countsOfLatestScans(ctx, id, ""); err != nil {
			return nil, err
		}
	}
	cutoff := s.now().UTC().Add(-staleAfter).Format(stampLayout)
	for i := range all {
		h := &all[i]
		h.Counts = counts[h.LatestScan]
		h.Profile = profile
		h.OtherProfile = profile != "" && h.Counts == nil && len(scored[h.LatestScan]) > 0
		if h.Counts == nil {
			h.Counts = Counts{}
		}
		h.Score = h.Counts.Score()
		h.Stale = h.LastScanAt == "" || h.LastScanAt < cutoff
	}
	return all, nil
}

// Hosts lists the hosts with the counts of their latest scan, sorted by name, and how many match.
func (s *Store) Hosts(ctx context.Context, f HostFilter) ([]HostSummary, int, error) {
	if f.Limit <= 0 {
		f.Limit = 100
	}
	f.Limit = min(f.Limit, 500)
	all, err := s.allHosts(ctx, f.Query, 0, f.StaleAfter, f.Profile)
	if err != nil {
		return nil, 0, err
	}
	out := make([]HostSummary, 0, len(all)) // never nil: the JSON is [], not null
	for _, h := range all {
		switch {
		case f.Status == "failing" && h.Counts["FAIL"] == 0, f.Status == "stale" && !h.Stale:
			continue
		}
		out = append(out, h)
	}
	switch f.Sort {
	case "score":
		sort.SliceStable(out, func(i, j int) bool {
			a, b := 2.0, 2.0 // undecided hosts last
			if out[i].Score != nil {
				a = *out[i].Score
			}
			if out[j].Score != nil {
				b = *out[j].Score
			}
			return a < b
		})
	case "last":
		sort.SliceStable(out, func(i, j int) bool { return out[i].LastScanAt < out[j].LastScanAt })
	}
	total := len(out)
	if f.All {
		return out, total, nil
	}
	if f.Offset >= len(out) {
		return []HostSummary{}, total, nil
	}
	page := out[f.Offset:min(len(out), f.Offset+f.Limit)]
	if err := s.addTrends(ctx, page, f.Profile); err != nil {
		return nil, 0, err
	}
	return page, total, nil
}

// addTrends sets the trend of the hosts of one page: the pass rate of each of their latest scans.
func (s *Store) addTrends(ctx context.Context, page []HostSummary, profile string) error {
	if len(page) == 0 {
		return nil
	}
	ids := make([]any, 0, len(page)+2)
	marks := make([]string, 0, len(page))
	byHost := map[int64]*HostSummary{}
	for i := range page {
		ids = append(ids, page[i].ID)
		marks = append(marks, "?")
		byHost[page[i].ID] = &page[i]
	}
	ids = append(ids, profile, profile)
	// The IN list is only "?" marks and the limit is a constant: nothing a request says is in the text of the query.
	//nolint:gosec // only "?" marks and a constant are joined in
	query := `
		WITH ranked AS (
		  SELECT id, host_row, ROW_NUMBER() OVER (PARTITION BY host_row ORDER BY received_at DESC, id DESC) AS rn
		  FROM scans WHERE host_row IN (` + strings.Join(marks, ",") + `)
		)
		SELECT r.host_row, r.rn, c.status, COUNT(*) FROM ranked r JOIN scan_controls c ON c.scan_row = r.id
		WHERE r.rn <= ` + strconv.Itoa(trendScans) + ` AND (? = '' OR c.profile = ?)
		GROUP BY r.host_row, r.rn, c.status`
	rs, err := s.db.QueryContext(ctx, query, ids...)
	if err != nil {
		return err
	}
	defer rs.Close()
	type key struct {
		host int64
		rn   int
	}
	perScan := map[key]Counts{}
	for rs.Next() {
		var k key
		var status string
		var n int
		if err := rs.Scan(&k.host, &k.rn, &status, &n); err != nil {
			return err
		}
		if perScan[k] == nil {
			perScan[k] = Counts{}
		}
		perScan[k][status] = n
	}
	if err := rs.Err(); err != nil {
		return err
	}
	for id, h := range byHost {
		for rn := trendScans; rn >= 1; rn-- { // oldest first
			if sc := perScan[key{id, rn}].Score(); sc != nil {
				h.Trend = append(h.Trend, *sc)
			}
		}
	}
	return nil
}

func likeEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

// countsOfLatestScans counts the controls of every host's latest scan by status, by scan row.
func (s *Store) countsOfLatestScans(ctx context.Context, hostRow int64, profile string) (map[int64]Counts, error) {
	rs, err := s.db.QueryContext(ctx, `
		SELECT c.scan_row, c.status, COUNT(*) FROM scan_controls c JOIN (`+latestScans+`) l ON l.id = c.scan_row
		WHERE (? = 0 OR l.host_row = ?) AND (? = '' OR c.profile = ?)
		GROUP BY c.scan_row, c.status`, hostRow, hostRow, profile, profile)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	out := map[int64]Counts{}
	for rs.Next() {
		var row int64
		var status string
		var n int
		if err := rs.Scan(&row, &status, &n); err != nil {
			return nil, err
		}
		if out[row] == nil {
			out[row] = Counts{}
		}
		out[row][status] = n
	}
	return out, rs.Err()
}

// ControlRow is one control of a scan.
type ControlRow struct {
	Profile  string `json:"profile"`
	ID       string `json:"id"`
	Title    string `json:"title"`
	TitleKo  string `json:"titleKo,omitempty"`
	Severity string `json:"severity"`
	Status   string `json:"status"`
}

// ScanRow is one scan of a host in its history.
type ScanRow struct {
	ID          int64    `json:"id"`
	ReceivedAt  string   `json:"receivedAt"`
	StartedAt   string   `json:"startedAt"`
	ToolVersion string   `json:"toolVersion"`
	Counts      Counts   `json:"counts"`
	Score       *float64 `json:"score"`
	Signed      bool     `json:"signed"`
}

// HostDetail is a host with the controls of its latest scan and its history, newest first.
type HostDetail struct {
	HostSummary
	// Profiles are the profiles of the latest scan; Controls are those of the selected one (all of them without a choice).
	Profiles []string     `json:"profiles"`
	Controls []ControlRow `json:"controls"`
	Scans    []ScanRow    `json:"scans"`
}

// Host returns one host.
func (s *Store) Host(ctx context.Context, id int64, staleAfter time.Duration, profile string) (*HostDetail, error) {
	list, err := s.allHosts(ctx, "", id, staleAfter, profile)
	if err != nil {
		return nil, err
	}
	if len(list) == 0 {
		return nil, ErrNotFound
	}
	d := &HostDetail{HostSummary: list[0]}
	d.Controls = []ControlRow{}
	d.Profiles = []string{}
	if d.LatestScan != 0 {
		ps, err := s.db.QueryContext(ctx, `SELECT DISTINCT profile FROM scan_controls WHERE scan_row = ? ORDER BY profile`, d.LatestScan)
		if err != nil {
			return nil, err
		}
		for ps.Next() {
			var p string
			if err := ps.Scan(&p); err != nil {
				_ = ps.Close()
				return nil, err
			}
			d.Profiles = append(d.Profiles, p)
		}
		if err := ps.Err(); err != nil {
			return nil, err
		}
		_ = ps.Close()
		rs, err := s.db.QueryContext(ctx, `SELECT profile, control_id, title, severity, status FROM scan_controls WHERE scan_row = ? AND (? = '' OR profile = ?) ORDER BY profile, control_id`, d.LatestScan, profile, profile)
		if err != nil {
			return nil, err
		}
		for rs.Next() {
			var c ControlRow
			if err := rs.Scan(&c.Profile, &c.ID, &c.Title, &c.Severity, &c.Status); err != nil {
				_ = rs.Close()
				return nil, err
			}
			d.Controls = append(d.Controls, c)
		}
		if err := rs.Err(); err != nil {
			return nil, err
		}
		_ = rs.Close()
	}
	d.Scans = []ScanRow{}
	rs, err := s.db.QueryContext(ctx, `
		SELECT s.id, s.received_at, s.started_at, s.tool_version, s.signature != '', c.status, COUNT(c.status)
		FROM (SELECT * FROM scans WHERE host_row = ? ORDER BY received_at DESC, id DESC LIMIT 200) s
		LEFT JOIN scan_controls c ON c.scan_row = s.id AND (? = '' OR c.profile = ?)
		GROUP BY s.id, c.status ORDER BY s.received_at DESC, s.id DESC`, id, profile, profile)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	byID := map[int64]*ScanRow{}
	for rs.Next() {
		var r ScanRow
		var status sql.NullString
		var n int
		if err := rs.Scan(&r.ID, &r.ReceivedAt, &r.StartedAt, &r.ToolVersion, &r.Signed, &status, &n); err != nil {
			return nil, err
		}
		row := byID[r.ID]
		if row == nil {
			r.Counts = Counts{}
			d.Scans = append(d.Scans, r)
			row = &d.Scans[len(d.Scans)-1]
			byID[r.ID] = row
		}
		if status.Valid {
			row.Counts[status.String] = n
		}
	}
	if err := rs.Err(); err != nil {
		return nil, err
	}
	for i := range d.Scans {
		d.Scans[i].Score = d.Scans[i].Counts.Score()
	}
	return d, nil
}

// maxStoredDoc bounds what a stored document is expanded to.
const maxStoredDoc = 64 << 20

// ScanDoc returns the document of a scan exactly as it was received.
func (s *Store) ScanDoc(ctx context.Context, id int64) ([]byte, error) {
	var gz []byte
	err := s.db.QueryRowContext(ctx, `SELECT doc FROM scans WHERE id = ?`, id).Scan(&gz)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		return nil, fmt.Errorf("scan %d: %w", id, err)
	}
	defer zr.Close()
	return io.ReadAll(io.LimitReader(zr, maxStoredDoc))
}

// RegressedControl is a control that got worse in a host's latest scan.
type RegressedControl struct {
	HostID     int64  `json:"hostId"`
	Host       string `json:"host"`
	Profile    string `json:"profile"`
	ControlID  string `json:"id"`
	Title      string `json:"title"`
	TitleKo    string `json:"titleKo,omitempty"`
	Severity   string `json:"severity"`
	Status     string `json:"status"`
	ReceivedAt string `json:"receivedAt"`
}

// FailingControl is a control that fails on many hosts.
type FailingControl struct {
	Profile  string `json:"profile"`
	ID       string `json:"id"`
	Title    string `json:"title"`
	TitleKo  string `json:"titleKo,omitempty"`
	Severity string `json:"severity"`
	Hosts    int    `json:"hosts"`
}

// Overview is the numbers of the dashboard's first page.
type Overview struct {
	Hosts        int `json:"hosts"`
	HostsFailing int `json:"hostsFailing"`
	HostsStale   int `json:"hostsStale"`
	// Profile is the profile the numbers are of; HostsOther counts the hosts whose latest scan has none of its controls.
	Profile          string             `json:"profile"`
	HostsOther       int                `json:"hostsOther"`
	Counts           Counts             `json:"counts"`
	Score            *float64           `json:"score"`
	TopFailing       []FailingControl   `json:"topFailing"`
	RecentRegression []RegressedControl `json:"recentRegressions"`
	StaleAfterDays   int                `json:"staleAfterDays"`
}

// Overview computes the first page of the dashboard. A host is stale when it has not reported
// for staleAfter; regressions are looked for in scans received within the same time.
func (s *Store) Overview(ctx context.Context, staleAfter time.Duration, profile string) (*Overview, error) {
	if staleAfter == 0 {
		staleAfter = 7 * 24 * time.Hour
	}
	hosts, err := s.allHosts(ctx, "", 0, staleAfter, profile)
	if err != nil {
		return nil, err
	}
	o := &Overview{Counts: Counts{}, TopFailing: []FailingControl{}, RecentRegression: []RegressedControl{}, StaleAfterDays: int(staleAfter.Hours() / 24), Profile: profile}
	for _, h := range hosts {
		if h.Stale {
			o.HostsStale++ // that a host is silent does not depend on the profile it scanned with
		}
		if h.OtherProfile {
			o.HostsOther++ // scanned with another profile: not counted in the rest
			continue
		}
		o.Hosts++
		if h.Counts["FAIL"] > 0 {
			o.HostsFailing++
		}
		for st, n := range h.Counts {
			o.Counts[st] += n
		}
	}
	o.Score = o.Counts.Score()

	rs, err := s.db.QueryContext(ctx, `
		SELECT c.profile, c.control_id, MAX(c.title), MAX(c.severity), COUNT(*)
		FROM scan_controls c JOIN (`+latestScans+`) l ON l.id = c.scan_row
		WHERE c.status = 'FAIL' AND (? = '' OR c.profile = ?) GROUP BY c.profile, c.control_id
		ORDER BY COUNT(*) DESC, c.control_id LIMIT 10`, profile, profile)
	if err != nil {
		return nil, err
	}
	for rs.Next() {
		var f FailingControl
		if err := rs.Scan(&f.Profile, &f.ID, &f.Title, &f.Severity, &f.Hosts); err != nil {
			_ = rs.Close()
			return nil, err
		}
		o.TopFailing = append(o.TopFailing, f)
	}
	if err := rs.Err(); err != nil {
		return nil, err
	}
	_ = rs.Close()

	cutoff := s.now().UTC().Add(-staleAfter).Format(stampLayout)
	rr, err := s.db.QueryContext(ctx, `
		WITH ranked AS (
		  SELECT id, host_row, received_at, ROW_NUMBER() OVER (PARTITION BY host_row ORDER BY received_at DESC, id DESC) AS rn FROM scans
		)
		SELECT h.id, h.name, c.profile, c.control_id, c.title, c.severity, c.status, l.received_at
		FROM ranked l
		JOIN ranked pv ON pv.host_row = l.host_row AND pv.rn = 2
		JOIN hosts h ON h.id = l.host_row
		JOIN scan_controls c ON c.scan_row = l.id AND c.status IN ('FAIL', 'ERROR')
		LEFT JOIN scan_controls p ON p.scan_row = pv.id AND p.profile = c.profile AND p.control_id = c.control_id
		WHERE l.rn = 1 AND (p.status IS NULL OR p.status NOT IN ('FAIL', 'ERROR')) AND l.received_at >= ? AND (? = '' OR c.profile = ?)
		ORDER BY l.received_at DESC, h.name, c.control_id LIMIT 20`, cutoff, profile, profile)
	if err != nil {
		return nil, err
	}
	defer rr.Close()
	for rr.Next() {
		var r RegressedControl
		if err := rr.Scan(&r.HostID, &r.Host, &r.Profile, &r.ControlID, &r.Title, &r.Severity, &r.Status, &r.ReceivedAt); err != nil {
			return nil, err
		}
		o.RecentRegression = append(o.RecentRegression, r)
	}
	return o, rr.Err()
}

// MatrixControl is a column of the matrix.
type MatrixControl struct {
	Profile  string `json:"profile"`
	ID       string `json:"id"`
	Title    string `json:"title"`
	TitleKo  string `json:"titleKo,omitempty"`
	Severity string `json:"severity"`
}

// MatrixHost is a row: the status of every column in the latest scan of the host, as one
// letter each (F fail, E error, M manual, W waived, P pass, N not applicable, - not in the scan).
type MatrixHost struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	Stale    bool   `json:"stale"`
	Statuses string `json:"statuses"`
}

// Matrix is the hosts × controls view of the latest scans.
type Matrix struct {
	Controls []MatrixControl `json:"controls"`
	Hosts    []MatrixHost    `json:"hosts"`
	Profile  string          `json:"profile"`
	// Other counts the hosts left out because their latest scan has none of the profile's controls.
	Other int `json:"other"`
}

var statusLetter = map[string]byte{"FAIL": 'F', "ERROR": 'E', "MANUAL": 'M', "WAIVED": 'W', "PASS": 'P', "NOT_APPLICABLE": 'N'}

// Matrix returns the latest status of every control on every host, hosts that fail most first.
func (s *Store) Matrix(ctx context.Context, staleAfter time.Duration, profile string) (*Matrix, error) {
	hosts, err := s.allHosts(ctx, "", 0, staleAfter, profile)
	if err != nil {
		return nil, err
	}
	rs, err := s.db.QueryContext(ctx, `
		SELECT c.scan_row, c.profile, c.control_id, c.title, c.severity, c.status
		FROM scan_controls c JOIN (`+latestScans+`) l ON l.id = c.scan_row
		WHERE ? = '' OR c.profile = ?`, profile, profile)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	type key struct{ profile, id string }
	var order []key
	cols := map[key]MatrixControl{}
	byScan := map[int64]map[key]byte{}
	for rs.Next() {
		var scan int64
		var c MatrixControl
		var status string
		if err := rs.Scan(&scan, &c.Profile, &c.ID, &c.Title, &c.Severity, &status); err != nil {
			return nil, err
		}
		k := key{c.Profile, c.ID}
		if _, ok := cols[k]; !ok {
			cols[k] = c
			order = append(order, k)
		}
		if byScan[scan] == nil {
			byScan[scan] = map[key]byte{}
		}
		byScan[scan][k] = statusLetter[status]
	}
	if err := rs.Err(); err != nil {
		return nil, err
	}
	sort.Slice(order, func(i, j int) bool {
		a, b := order[i], order[j]
		if a.profile != b.profile {
			return a.profile < b.profile
		}
		return naturalLess(a.id, b.id)
	})
	m := &Matrix{Controls: make([]MatrixControl, 0, len(order)), Hosts: make([]MatrixHost, 0, len(hosts)), Profile: profile}
	for _, k := range order {
		m.Controls = append(m.Controls, cols[k])
	}
	for _, h := range hosts {
		if h.OtherProfile {
			m.Other++ // scanned with another profile: not a row of this one
			continue
		}
		row := make([]byte, len(order))
		for i, k := range order {
			if st, ok := byScan[h.LatestScan][k]; ok && st != 0 {
				row[i] = st
			} else {
				row[i] = '-'
			}
		}
		m.Hosts = append(m.Hosts, MatrixHost{ID: h.ID, Name: h.Name, Stale: h.Stale, Statuses: string(row)})
	}
	// Hosts with the most failing controls first, then by name.
	sort.SliceStable(m.Hosts, func(i, j int) bool {
		fi, fj := strings.Count(m.Hosts[i].Statuses, "F"), strings.Count(m.Hosts[j].Statuses, "F")
		return fi > fj
	})
	return m, nil
}

// naturalLess orders "U-2" before "U-10".
func naturalLess(a, b string) bool {
	ia, ib := 0, 0
	for ia < len(a) && ib < len(b) {
		if isDigit(a[ia]) && isDigit(b[ib]) {
			ja, jb := ia, ib
			for ja < len(a) && isDigit(a[ja]) {
				ja++
			}
			for jb < len(b) && isDigit(b[jb]) {
				jb++
			}
			na, nb := strings.TrimLeft(a[ia:ja], "0"), strings.TrimLeft(b[ib:jb], "0")
			if len(na) != len(nb) {
				return len(na) < len(nb)
			}
			if na != nb {
				return na < nb
			}
			ia, ib = ja, jb
			continue
		}
		if a[ia] != b[ib] {
			return a[ia] < b[ib]
		}
		ia++
		ib++
	}
	return len(a)-ia < len(b)-ib
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// ControlSummary is one control across the fleet: how many hosts have each status in their latest scan.
type ControlSummary struct {
	Profile  string `json:"profile"`
	ID       string `json:"id"`
	Title    string `json:"title"`
	TitleKo  string `json:"titleKo,omitempty"`
	Severity string `json:"severity"`
	Counts   Counts `json:"counts"`
}

// Controls lists every control with the status counts of the latest scans.
func (s *Store) Controls(ctx context.Context, profile string) ([]ControlSummary, error) {
	rs, err := s.db.QueryContext(ctx, `
		SELECT c.profile, c.control_id, MAX(c.title), MAX(c.severity), c.status, COUNT(*)
		FROM scan_controls c JOIN (`+latestScans+`) l ON l.id = c.scan_row
		WHERE ? = '' OR c.profile = ?
		GROUP BY c.profile, c.control_id, c.status`, profile, profile)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	type key struct{ profile, id string }
	byKey := map[key]*ControlSummary{}
	var order []key
	for rs.Next() {
		var c ControlSummary
		var status string
		var n int
		if err := rs.Scan(&c.Profile, &c.ID, &c.Title, &c.Severity, &status, &n); err != nil {
			return nil, err
		}
		k := key{c.Profile, c.ID}
		cur := byKey[k]
		if cur == nil {
			c.Counts = Counts{}
			cur = &c
			byKey[k] = cur
			order = append(order, k)
		}
		cur.Counts[status] = n
	}
	if err := rs.Err(); err != nil {
		return nil, err
	}
	sort.Slice(order, func(i, j int) bool {
		a, b := order[i], order[j]
		if a.profile != b.profile {
			return a.profile < b.profile
		}
		return naturalLess(a.id, b.id)
	})
	out := make([]ControlSummary, 0, len(order))
	for _, k := range order {
		out = append(out, *byKey[k])
	}
	return out, nil
}

// ControlHost is a host's status for one control.
type ControlHost struct {
	HostID int64  `json:"hostId"`
	Host   string `json:"host"`
	Status string `json:"status"`
	Stale  bool   `json:"stale"`
}

// ControlDetail is one control: the hosts, worst status first.
type ControlDetail struct {
	ControlSummary
	Hosts []ControlHost `json:"hosts"`
}

// Control returns the status of one control on every host that has a scan.
func (s *Store) Control(ctx context.Context, profile, id string, staleAfter time.Duration) (*ControlDetail, error) {
	hosts, err := s.allHosts(ctx, "", 0, staleAfter, "")
	if err != nil {
		return nil, err
	}
	stale := map[int64]bool{}
	for _, h := range hosts {
		stale[h.ID] = h.Stale
	}
	rs, err := s.db.QueryContext(ctx, `
		SELECT h.id, h.name, c.title, c.severity, c.status
		FROM scan_controls c JOIN (`+latestScans+`) l ON l.id = c.scan_row JOIN hosts h ON h.id = l.host_row
		WHERE c.profile = ? AND c.control_id = ? ORDER BY h.name`, profile, id)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	d := &ControlDetail{ControlSummary: ControlSummary{Profile: profile, ID: id, Counts: Counts{}}, Hosts: []ControlHost{}}
	for rs.Next() {
		var h ControlHost
		var title, sev string
		if err := rs.Scan(&h.HostID, &h.Host, &title, &sev, &h.Status); err != nil {
			return nil, err
		}
		h.Stale = stale[h.HostID]
		d.Title, d.Severity = title, sev
		d.Counts[h.Status]++
		d.Hosts = append(d.Hosts, h)
	}
	if err := rs.Err(); err != nil {
		return nil, err
	}
	if len(d.Hosts) == 0 {
		return nil, ErrNotFound
	}
	rank := map[string]int{}
	for i, st := range statusOrder {
		rank[st] = i
	}
	sort.SliceStable(d.Hosts, func(i, j int) bool { return rank[d.Hosts[i].Status] < rank[d.Hosts[j].Status] })
	return d, nil
}

// ProfileUse is a profile that the latest scans have controls of, and how many hosts that is.
type ProfileUse struct {
	ID    string `json:"id"`
	Hosts int    `json:"hosts"`
}

// Profiles lists the profiles of the latest scans, the one most hosts use first (then by name).
func (s *Store) Profiles(ctx context.Context) ([]ProfileUse, error) {
	rs, err := s.db.QueryContext(ctx, `
		SELECT c.profile, COUNT(DISTINCT l.host_row)
		FROM scan_controls c JOIN (`+latestScans+`) l ON l.id = c.scan_row
		GROUP BY c.profile ORDER BY COUNT(DISTINCT l.host_row) DESC, c.profile`)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	out := []ProfileUse{}
	for rs.Next() {
		var u ProfileUse
		if err := rs.Scan(&u.ID, &u.Hosts); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rs.Err()
}

// TrendPoint is the fleet at one moment: each host's latest scan until then, counted.
type TrendPoint struct {
	At      string   `json:"at"`
	Hosts   int      `json:"hosts"`
	Failing int      `json:"failing"` // hosts with a FAIL control
	Score   *float64 `json:"score"`
	Counts  Counts   `json:"counts"`
}

// Trend is the fleet over the last days, one point a day, the last one now (oldest first). A host counts from its
// first scan on; what a host did not report yet is not counted (a day before the first scan has no hosts).
func (s *Store) Trend(ctx context.Context, days int, profile string) ([]TrendPoint, error) {
	days = max(1, min(days, 90))
	now := s.now().UTC()
	points := make([]TrendPoint, 0, days)
	for i := days - 1; i >= 0; i-- {
		at := now.Add(-time.Duration(i) * 24 * time.Hour)
		stamp := at.Format(stampLayout)
		p := TrendPoint{At: at.Format(time.RFC3339), Counts: Counts{}}
		rs, err := s.db.QueryContext(ctx, `
			SELECT c.status, COUNT(*), COUNT(DISTINCT s.id)
			FROM hosts h
			JOIN scans s ON s.id = (SELECT id FROM scans WHERE host_row = h.id AND received_at <= ? ORDER BY received_at DESC, id DESC LIMIT 1)
			JOIN scan_controls c ON c.scan_row = s.id
			WHERE (? = '' OR c.profile = ?)
			GROUP BY c.status`, stamp, profile, profile)
		if err != nil {
			return nil, err
		}
		for rs.Next() {
			var status string
			var n, scans int
			if err := rs.Scan(&status, &n, &scans); err != nil {
				_ = rs.Close()
				return nil, err
			}
			p.Counts[status] = n
			if status == "FAIL" {
				p.Failing = scans
			}
		}
		if err := rs.Err(); err != nil {
			_ = rs.Close()
			return nil, err
		}
		_ = rs.Close()
		if err := s.db.QueryRowContext(ctx, `
			SELECT COUNT(DISTINCT s.id)
			FROM hosts h
			JOIN scans s ON s.id = (SELECT id FROM scans WHERE host_row = h.id AND received_at <= ? ORDER BY received_at DESC, id DESC LIMIT 1)
			JOIN scan_controls c ON c.scan_row = s.id
			WHERE (? = '' OR c.profile = ?)`, stamp, profile, profile).Scan(&p.Hosts); err != nil {
			return nil, err
		}
		p.Score = p.Counts.Score()
		points = append(points, p)
	}
	return points, nil
}
