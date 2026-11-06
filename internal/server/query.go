package server

import (
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
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
}

// HostFilter selects and pages the host list.
type HostFilter struct {
	Query      string        // part of the host name
	Status     string        // "failing" (a FAIL control), "stale", or "" for all
	StaleAfter time.Duration // a host that has not reported for this long is stale (7 days when 0)
	Limit      int           // 100 when 0, at most 500
	Offset     int
	All        bool // every match: no paging (the export)
}

const latestScans = `SELECT id, host_row FROM scans s WHERE id = (SELECT id FROM scans WHERE host_row = s.host_row ORDER BY received_at DESC, id DESC LIMIT 1)`

// allHosts returns every host whose name contains query (and the host with id, when id is not
// 0) with the counts of its latest scan, sorted by name.
func (s *Store) allHosts(ctx context.Context, query string, id int64, staleAfter time.Duration) ([]HostSummary, error) {
	if staleAfter == 0 {
		staleAfter = 7 * 24 * time.Hour
	}
	rs, err := s.db.QueryContext(ctx, `
		SELECT h.id, h.name, h.host_id, COALESCE(h.last_scan_at, ''), COALESCE(l.id, 0)
		FROM hosts h LEFT JOIN (`+latestScans+`) l ON l.host_row = h.id
		WHERE h.name LIKE ? ESCAPE '\' AND (? = 0 OR h.id = ?)
		ORDER BY h.name, h.id`, "%"+likeEscape(query)+"%", id, id)
	if err != nil {
		return nil, err
	}
	var all []HostSummary
	for rs.Next() {
		var h HostSummary
		if err := rs.Scan(&h.ID, &h.Name, &h.HostID, &h.LastScanAt, &h.LatestScan); err != nil {
			_ = rs.Close()
			return nil, err
		}
		all = append(all, h)
	}
	if err := rs.Err(); err != nil {
		return nil, err
	}
	_ = rs.Close()
	counts, err := s.countsOfLatestScans(ctx, id)
	if err != nil {
		return nil, err
	}
	cutoff := s.now().UTC().Add(-staleAfter).Format(stampLayout)
	for i := range all {
		h := &all[i]
		h.Counts = counts[h.LatestScan]
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
	all, err := s.allHosts(ctx, f.Query, 0, f.StaleAfter)
	if err != nil {
		return nil, 0, err
	}
	out := all[:0]
	for _, h := range all {
		switch {
		case f.Status == "failing" && h.Counts["FAIL"] == 0, f.Status == "stale" && !h.Stale:
			continue
		}
		out = append(out, h)
	}
	total := len(out)
	if f.All {
		return out, total, nil
	}
	if f.Offset >= len(out) {
		return []HostSummary{}, total, nil
	}
	return out[f.Offset:min(len(out), f.Offset+f.Limit)], total, nil
}

func likeEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

// countsOfLatestScans counts the controls of every host's latest scan by status, by scan row.
func (s *Store) countsOfLatestScans(ctx context.Context, hostRow int64) (map[int64]Counts, error) {
	rs, err := s.db.QueryContext(ctx, `
		SELECT c.scan_row, c.status, COUNT(*) FROM scan_controls c JOIN (`+latestScans+`) l ON l.id = c.scan_row
		WHERE ? = 0 OR l.host_row = ?
		GROUP BY c.scan_row, c.status`, hostRow, hostRow)
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
}

// HostDetail is a host with the controls of its latest scan and its history, newest first.
type HostDetail struct {
	HostSummary
	Controls []ControlRow `json:"controls"`
	Scans    []ScanRow    `json:"scans"`
}

// Host returns one host.
func (s *Store) Host(ctx context.Context, id int64, staleAfter time.Duration) (*HostDetail, error) {
	list, err := s.allHosts(ctx, "", id, staleAfter)
	if err != nil {
		return nil, err
	}
	if len(list) == 0 {
		return nil, ErrNotFound
	}
	d := &HostDetail{HostSummary: list[0]}
	d.Controls = []ControlRow{}
	if d.LatestScan != 0 {
		rs, err := s.db.QueryContext(ctx, `SELECT profile, control_id, title, severity, status FROM scan_controls WHERE scan_row = ? ORDER BY profile, control_id`, d.LatestScan)
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
		SELECT s.id, s.received_at, s.started_at, s.tool_version, c.status, COUNT(c.status)
		FROM (SELECT * FROM scans WHERE host_row = ? ORDER BY received_at DESC, id DESC LIMIT 200) s
		LEFT JOIN scan_controls c ON c.scan_row = s.id
		GROUP BY s.id, c.status ORDER BY s.received_at DESC, s.id DESC`, id)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	byID := map[int64]*ScanRow{}
	for rs.Next() {
		var r ScanRow
		var status sql.NullString
		var n int
		if err := rs.Scan(&r.ID, &r.ReceivedAt, &r.StartedAt, &r.ToolVersion, &status, &n); err != nil {
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
	Severity   string `json:"severity"`
	Status     string `json:"status"`
	ReceivedAt string `json:"receivedAt"`
}

// FailingControl is a control that fails on many hosts.
type FailingControl struct {
	Profile  string `json:"profile"`
	ID       string `json:"id"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	Hosts    int    `json:"hosts"`
}

// Overview is the numbers of the dashboard's first page.
type Overview struct {
	Hosts            int                `json:"hosts"`
	HostsFailing     int                `json:"hostsFailing"`
	HostsStale       int                `json:"hostsStale"`
	Counts           Counts             `json:"counts"`
	Score            *float64           `json:"score"`
	TopFailing       []FailingControl   `json:"topFailing"`
	RecentRegression []RegressedControl `json:"recentRegressions"`
	StaleAfterDays   int                `json:"staleAfterDays"`
}

// Overview computes the first page of the dashboard. A host is stale when it has not reported
// for staleAfter; regressions are looked for in scans received within the same time.
func (s *Store) Overview(ctx context.Context, staleAfter time.Duration) (*Overview, error) {
	if staleAfter == 0 {
		staleAfter = 7 * 24 * time.Hour
	}
	hosts, err := s.allHosts(ctx, "", 0, staleAfter)
	if err != nil {
		return nil, err
	}
	o := &Overview{Counts: Counts{}, TopFailing: []FailingControl{}, RecentRegression: []RegressedControl{}, StaleAfterDays: int(staleAfter.Hours() / 24)}
	for _, h := range hosts {
		o.Hosts++
		if h.Counts["FAIL"] > 0 {
			o.HostsFailing++
		}
		if h.Stale {
			o.HostsStale++
		}
		for st, n := range h.Counts {
			o.Counts[st] += n
		}
	}
	o.Score = o.Counts.Score()

	rs, err := s.db.QueryContext(ctx, `
		SELECT c.profile, c.control_id, MAX(c.title), MAX(c.severity), COUNT(*)
		FROM scan_controls c JOIN (`+latestScans+`) l ON l.id = c.scan_row
		WHERE c.status = 'FAIL' GROUP BY c.profile, c.control_id
		ORDER BY COUNT(*) DESC, c.control_id LIMIT 10`)
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
		WHERE l.rn = 1 AND (p.status IS NULL OR p.status NOT IN ('FAIL', 'ERROR')) AND l.received_at >= ?
		ORDER BY l.received_at DESC, h.name, c.control_id LIMIT 20`, cutoff)
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
