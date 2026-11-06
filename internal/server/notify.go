package server

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// HeaderWebhookSignature carries "sha256=" and the hex HMAC-SHA256 of the request body, when a secret is set.
const HeaderWebhookSignature = "X-Hostlint-Signature-256"

// Webhook is where the server reports events: a host got worse, a host went silent. It is a URL the
// operator chose; the server posts JSON to it and reads nothing back.
type Webhook struct {
	URL    string
	Secret []byte
	// Client is the HTTP client; nil makes one that follows no redirects and gives up after 10 seconds.
	Client *http.Client
}

// ValidateWebhookURL accepts https, or http to a loopback host (for a local relay and tests).
func ValidateWebhookURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil {
		return errors.New("the webhook URL is not a valid URL without credentials")
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if isLoopback(u.Host) || isLoopback(u.Host+":0") {
			return nil
		}
	}
	return errors.New("the webhook URL must be https (http only to a loopback address)")
}

// Event is what is posted. Text is a one-line summary that chat services with incoming webhooks
// (Slack, Mattermost, Discord's Slack-compatible endpoint) show as it is. It carries control IDs and
// statuses only, never evidence.
type Event struct {
	Event     string           `json:"event"` // "regression" or "stale"
	Text      string           `json:"text"`
	At        string           `json:"at"`
	Host      string           `json:"host"`
	HostID    string           `json:"hostId"`
	Scan      string           `json:"scan,omitempty"`
	LastScan  string           `json:"lastScan,omitempty"` // stale: when the host last reported
	Regressed []RegressedEntry `json:"regressed,omitempty"`
	More      int              `json:"more,omitempty"`
}

// RegressedEntry is a control that is FAIL or ERROR now and was not in the host's previous scan.
type RegressedEntry struct {
	Profile  string `json:"profile"`
	ID       string `json:"id"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	Old      string `json:"old"`
	New      string `json:"new"`
}

const maxRegressedInEvent = 20

// Send posts one event. Anything but a 2xx answer is an error.
func (w *Webhook) Send(ctx context.Context, ev Event) error {
	body, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(body))
	if err != nil {
		return errors.New("the webhook request could not be made") // not the error: it names the URL, which can be a secret
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "hostlint-server")
	if len(w.Secret) > 0 {
		mac := hmac.New(sha256.New, w.Secret)
		mac.Write(body)
		req.Header.Set(HeaderWebhookSignature, "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	client := w.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	resp, err := client.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) { // the URL is in a *url.Error; leave it out of the log
			err = ue.Err
		}
		return fmt.Errorf("posting the webhook: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("the webhook answered %d", resp.StatusCode)
	}
	return nil
}

// Notifier finds the events and has the webhook post them, at least once: a cursor moves on only after
// an event was delivered, so a webhook that is down gets everything when it is back.
type Notifier struct {
	Store      *Store
	Hook       *Webhook
	StaleAfter time.Duration // a host that has not reported for this long is reported (7 days by default)
	Logger     *slog.Logger
}

// Run checks every interval until ctx ends.
func (n *Notifier) Run(ctx context.Context, interval time.Duration) {
	for {
		if err := n.Tick(ctx); err != nil && ctx.Err() == nil && n.Logger != nil {
			n.Logger.Error("webhook", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}

func (s *Store) state(ctx context.Context, name string) (string, bool, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM notify_state WHERE name = ?`, name).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	return v, err == nil, err
}

func (s *Store) setState(ctx context.Context, name, value string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO notify_state (name, value) VALUES (?, ?) ON CONFLICT(name) DO UPDATE SET value = excluded.value`, name, value)
	return err
}

// Tick reports what is new since the last tick. Enabling the webhook does not report history: the
// cursor starts at the newest scan.
func (n *Notifier) Tick(ctx context.Context) error {
	st := n.Store
	cur, ok, err := st.state(ctx, "scan-cursor")
	if err != nil {
		return err
	}
	if !ok {
		var newest sql.NullInt64
		if err := st.db.QueryRowContext(ctx, `SELECT MAX(id) FROM scans`).Scan(&newest); err != nil {
			return err
		}
		cur = strconv.FormatInt(newest.Int64, 10)
		if err := st.setState(ctx, "scan-cursor", cur); err != nil {
			return err
		}
	}
	cursor, err := strconv.ParseInt(cur, 10, 64)
	if err != nil {
		return fmt.Errorf("the notification cursor is damaged: %w", err)
	}
	type newScan struct {
		id, host     int64
		scan, name   string
		hostID       string
		scanned      string
		hasPredecess bool
	}
	rs, err := st.db.QueryContext(ctx, `
		SELECT s.id, s.host_row, s.scan_id, h.name, h.host_id, s.started_at,
		       EXISTS (SELECT 1 FROM scans p WHERE p.host_row = s.host_row AND (p.received_at, p.id) < (s.received_at, s.id))
		FROM scans s JOIN hosts h ON h.id = s.host_row WHERE s.id > ? ORDER BY s.id LIMIT 200`, cursor)
	if err != nil {
		return err
	}
	var scans []newScan
	for rs.Next() {
		var x newScan
		if err := rs.Scan(&x.id, &x.host, &x.scan, &x.name, &x.hostID, &x.scanned, &x.hasPredecess); err != nil {
			_ = rs.Close()
			return err
		}
		scans = append(scans, x)
	}
	if err := rs.Err(); err != nil {
		return err
	}
	_ = rs.Close()
	for _, x := range scans {
		if x.hasPredecess {
			reg, err := st.regressedIn(ctx, x.id, x.host)
			if err != nil {
				return err
			}
			if len(reg) > 0 {
				ev := Event{Event: "regression", At: st.stamp(), Host: x.name, HostID: x.hostID, Scan: x.scan, Regressed: reg}
				if len(reg) > maxRegressedInEvent {
					ev.More, ev.Regressed = len(reg)-maxRegressedInEvent, reg[:maxRegressedInEvent]
				}
				ev.Text = fmt.Sprintf("hostlint: %s got worse: %d control(s) now fail (%s)", x.name, len(reg), joinIDs(reg))
				if err := n.Hook.Send(ctx, ev); err != nil {
					return err
				}
			}
		}
		if err := st.setState(ctx, "scan-cursor", strconv.FormatInt(x.id, 10)); err != nil {
			return err
		}
	}
	return n.tickStale(ctx)
}

func joinIDs(reg []RegressedEntry) string {
	ids := make([]string, 0, 3)
	for i, r := range reg {
		if i == 3 {
			ids = append(ids, "...")
			break
		}
		ids = append(ids, r.ID)
	}
	return strings.Join(ids, ", ")
}

// regressedIn lists the controls that are FAIL or ERROR in a scan and were not in the host's scan before it.
func (s *Store) regressedIn(ctx context.Context, scanRow, hostRow int64) ([]RegressedEntry, error) {
	rs, err := s.db.QueryContext(ctx, `
		SELECT c.profile, c.control_id, c.title, c.severity, COALESCE(p.status, ''), c.status
		FROM scans cur
		JOIN scans prev ON prev.id = (SELECT id FROM scans WHERE host_row = cur.host_row AND (received_at, id) < (cur.received_at, cur.id) ORDER BY received_at DESC, id DESC LIMIT 1)
		JOIN scan_controls c ON c.scan_row = cur.id AND c.status IN ('FAIL', 'ERROR')
		LEFT JOIN scan_controls p ON p.scan_row = prev.id AND p.profile = c.profile AND p.control_id = c.control_id
		WHERE cur.id = ? AND cur.host_row = ? AND (p.status IS NULL OR p.status NOT IN ('FAIL', 'ERROR'))
		ORDER BY c.profile, c.control_id`, scanRow, hostRow)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	var out []RegressedEntry
	for rs.Next() {
		var e RegressedEntry
		if err := rs.Scan(&e.Profile, &e.ID, &e.Title, &e.Severity, &e.Old, &e.New); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rs.Err()
}

// tickStale reports the hosts whose latest scan is older than StaleAfter, once per latest scan.
func (n *Notifier) tickStale(ctx context.Context) error {
	st := n.Store
	after := n.StaleAfter
	if after <= 0 {
		after = 7 * 24 * time.Hour
	}
	cutoff := st.now().UTC().Add(-after).Format(stampLayout)
	rs, err := st.db.QueryContext(ctx, `SELECT h.id, h.name, h.host_id, l.id, s.received_at FROM hosts h JOIN (`+latestScans+`) l ON l.host_row = h.id JOIN scans s ON s.id = l.id WHERE s.received_at < ? ORDER BY h.id`, cutoff)
	if err != nil {
		return err
	}
	type quiet struct {
		host, scan             int64
		name, hostID, received string
	}
	var qs []quiet
	for rs.Next() {
		var q quiet
		if err := rs.Scan(&q.host, &q.name, &q.hostID, &q.scan, &q.received); err != nil {
			_ = rs.Close()
			return err
		}
		qs = append(qs, q)
	}
	if err := rs.Err(); err != nil {
		return err
	}
	_ = rs.Close()
	for _, q := range qs {
		name := "silent-" + strconv.FormatInt(q.host, 10)
		last, _, err := st.state(ctx, name)
		if err != nil {
			return err
		}
		if last == strconv.FormatInt(q.scan, 10) {
			continue
		}
		ev := Event{Event: "stale", At: st.stamp(), Host: q.name, HostID: q.hostID, LastScan: q.received,
			Text: fmt.Sprintf("hostlint: %s has not reported since %s", q.name, q.received)}
		if err := n.Hook.Send(ctx, ev); err != nil {
			return err
		}
		if err := st.setState(ctx, name, strconv.FormatInt(q.scan, 10)); err != nil {
			return err
		}
	}
	return nil
}
