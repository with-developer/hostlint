// Package server is hostlint's fleet server: it receives scan results that hosts
// push, keeps them in SQLite and (in later changes) serves them to a dashboard.
// See docs/adr/0010-fleet-server-and-dashboard.md.
//
// A result is untrusted input from a possibly compromised host: it is validated,
// bounded and kept as text. The server has no channel to the hosts it knows about.
package server

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	_ "modernc.org/sqlite" // the pure-Go SQLite driver: the binary stays static

	"github.com/with-developer/hostlint/internal/engine"
	"github.com/with-developer/hostlint/internal/signing"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// Store is the server's database.
type Store struct {
	db  *sql.DB
	now func() time.Time
}

// OpenStore opens (and creates) the database at path and applies the migrations.
// path ":memory:" gives a private in-memory database, for tests.
func OpenStore(path string) (*Store, error) {
	if path != ":memory:" {
		if err := securePath(path); err != nil {
			return nil, err
		}
	}
	// Write transactions start with BEGIN IMMEDIATE (_txlock): the server and the command
	// line share the file, and a transaction that reads and then writes must not fail
	// halfway on another process's commit.
	dsn := "file:" + path + "?_txlock=immediate&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)"
	if path != ":memory:" {
		dsn += "&_pragma=journal_mode(WAL)"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// One writer at a time is what SQLite gives; one connection keeps it simple and
	// makes an in-memory database one database.
	db.SetMaxOpenConns(1)
	s := &Store{db: db, now: time.Now}
	if err := s.migrate(context.Background()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return s, nil
}

// securePath makes sure the database is private: the file is created with mode 0600 (SQLite
// gives its -wal and -shm files the same mode), and one that others can read is refused. It
// holds the raw results of the whole fleet.
func securePath(path string) error {
	fi, err := os.Stat(path) //nolint:forbidigo // the server's own database, not the scanned host
	switch {
	case errors.Is(err, fs.ErrNotExist):
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) //nolint:forbidigo,gosec // the server creates its own database (G304: --db)
		if err != nil {
			return err
		}
		return f.Close()
	case err != nil:
		return err
	case fi.Mode().Perm()&0o077 != 0:
		return fmt.Errorf("%s can be read by other users (mode %04o): run chmod 600 on it", path, fi.Mode().Perm())
	}
	return nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// migrate applies the numbered SQL files in migrations/ that have not run yet.
func (s *Store) migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)`); err != nil {
		return err
	}
	entries, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		return err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	for _, name := range names {
		version, err := migrationVersion(name)
		if err != nil {
			return err
		}
		var done int
		if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations WHERE version = ?`, version).Scan(&done); err != nil {
			return err
		}
		if done > 0 {
			continue
		}
		body, err := fs.ReadFile(migrationFS, "migrations/"+name)
		if err != nil {
			return err
		}
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		for _, stmt := range strings.Split(string(body), "\n;;\n") {
			if strings.TrimSpace(stmt) == "" {
				continue
			}
			if _, err := tx.ExecContext(ctx, stmt); err != nil {
				_ = tx.Rollback()
				return fmt.Errorf("migration %s: %w", name, err)
			}
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)`, version, s.stamp()); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// migrationVersion is the number at the start of a migration file name ("0001_init.sql").
func migrationVersion(name string) (int, error) {
	digits, _, _ := strings.Cut(name, "_")
	n, err := strconv.Atoi(digits)
	if err != nil || n < 1 {
		return 0, fmt.Errorf("migration file %q does not start with its version number", name)
	}
	return n, nil
}

// stampLayout has a fixed width, so that timestamps sort as text.
const stampLayout = "2006-01-02T15:04:05.000000000Z07:00"

func (s *Store) stamp() string { return s.now().UTC().Format(stampLayout) }

// Errors of an ingest that the caller answers with a status.
var (
	// ErrDuplicate means a scan with this ID was received for the host before, with other content.
	ErrDuplicate = errors.New("a scan with this ID was already received with different content")
	// ErrIdentity means the result claims a host the credential, or the known hosts, do not allow.
	ErrIdentity = errors.New("host identity conflict")
)

// IngestOption adds to an ingest.
type IngestOption func(*ingestOptions)

type ingestOptions struct{ key, sig string }

// WithSignature says the document was signed: key is the public key and sig the signature (both
// base64), already verified against the document by the caller.
func WithSignature(key, sig string) IngestOption {
	return func(o *ingestOptions) { o.key, o.sig = key, sig }
}

// IngestResult says what a received scan became.
type IngestResult struct {
	ScanRow    int64
	HostRow    int64
	ReceivedAt string
	Digest     string
	// Duplicate is true when the same document was received before: a retry. Nothing was stored.
	Duplicate bool
}

// IngestScan stores a validated result. raw is the document as received (kept
// unchanged next to the rows derived from it). It enforces the host identity rules of
// ADR 0010: a bound credential speaks for one host name and host ID; a known name never
// gets a second host ID; a scan ID is stored once per host. The same document sent again
// is a retry and is acknowledged without being stored twice.
func (s *Store) IngestScan(ctx context.Context, cred *Credential, res *engine.Result, raw []byte, remote string, opts ...IngestOption) (*IngestResult, error) {
	var in ingestOptions
	for _, o := range opts {
		o(&in)
	}
	sum := sha256.Sum256(raw)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	if _, err := zw.Write(raw); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}

	tx, err := s.db.BeginTx(ctx, nil) // BEGIN IMMEDIATE: what is read here is still true when written
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	// A token bound to a public key accepts only results signed with that key (no trust on first use).
	if cred.PubKey != "" && in.key != cred.PubKey {
		return nil, fmt.Errorf("%w: this token only accepts results signed with its key", ErrIdentity)
	}
	name, hostID := res.Host.Hostname, res.Host.HostID
	if cred.BoundName != "" {
		if !boundMatches(cred.BoundName, name) {
			return nil, fmt.Errorf("%w: the token is for host %q, the result is of %q", ErrIdentity, cred.BoundName, name)
		}
		// The first result pins the host ID; after that it must match. The pin is read in
		// this transaction, not taken from the request's earlier look at the credential.
		var pinned sql.NullString
		if err := tx.QueryRowContext(ctx, `SELECT bound_host_id FROM credentials WHERE id = ?`, cred.ID).Scan(&pinned); err != nil {
			return nil, err
		}
		switch {
		case pinned.String != "" && hostID != pinned.String:
			return nil, fmt.Errorf("%w: the host ID differs from the one this token was first used with", ErrIdentity)
		case pinned.String == "" && hostID != "":
			if _, err := tx.ExecContext(ctx, `UPDATE credentials SET bound_host_id = ? WHERE id = ? AND bound_host_id IS NULL`, hostID, cred.ID); err != nil {
				return nil, err
			}
		}
	}
	// A name that is known with another host ID is not merged: it may be another machine.
	var other int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM hosts WHERE name = ? AND host_id != ? AND host_id != ''`, name, hostID).Scan(&other); err != nil {
		return nil, err
	}
	switch {
	case other > 0 && hostID != "":
		return nil, fmt.Errorf("%w: the name %q is known with another host ID (if the machine was re-installed, remove the old host: hostlint server host delete)", ErrIdentity, name)
	case other > 0:
		return nil, fmt.Errorf("%w: the name %q is known with a host ID and this result has none", ErrIdentity, name)
	}
	// A name is a host or an image, not both: a result must not take over the row of the other kind.
	kind := kindHost
	if res.Scan.Target.Image != nil {
		kind = kindImage
	}
	// A prefix token is for the images of an organization's CI: it does not make hosts that count in the fleet's numbers.
	if kind != kindImage && strings.HasSuffix(cred.BoundName, "*") {
		return nil, fmt.Errorf("%w: a token bound to a prefix is for images, and this is the result of a host", ErrIdentity)
	}
	var otherKind int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM hosts WHERE name = ? AND kind != ?`, name, kind).Scan(&otherKind); err != nil {
		return nil, err
	}
	if otherKind > 0 {
		return nil, fmt.Errorf("%w: the name %q is already used by %s", ErrIdentity, name, map[string]string{kindHost: "an image", kindImage: "a host"}[kind])
	}
	received := s.stamp()
	if hostID != "" {
		// A host that first sent no ID and now sends one is the same host: its row takes the ID.
		if _, err := tx.ExecContext(ctx, `UPDATE hosts SET host_id = ? WHERE name = ? AND host_id = ''`, hostID, name); err != nil {
			return nil, err
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO hosts (name, host_id, created_at, kind) VALUES (?, ?, ?, ?)`, name, hostID, received, kind); err != nil {
		return nil, err
	}
	var hostRow int64
	var hostKey string
	if err := tx.QueryRowContext(ctx, `SELECT id, pubkey FROM hosts WHERE name = ? AND host_id = ?`, name, hostID).Scan(&hostRow, &hostKey); err != nil {
		return nil, err
	}
	// A host that has signed before keeps signing, with the same key: an unsigned result, or one
	// signed with another key, is what a thief of the token (or a compromised host) would send.
	switch {
	case hostKey != "" && in.key == "":
		return nil, fmt.Errorf("%w: this host sends signed results, and this one is not signed", ErrIdentity)
	case hostKey != "" && in.key != hostKey:
		return nil, fmt.Errorf("%w: signed with another key than the one registered for this host (reset it with: hostlint server host reset-key)", ErrIdentity)
	case hostKey == "" && in.key != "":
		if _, err := tx.ExecContext(ctx, `UPDATE hosts SET pubkey = ? WHERE id = ?`, in.key, hostRow); err != nil {
			return nil, err
		}
	}
	imageRef, imageDigest := "", ""
	if img := res.Scan.Target.Image; img != nil {
		imageRef, imageDigest = img.Ref, img.Digest // bounded by checkLimits
	}
	r, err := tx.ExecContext(ctx,
		`INSERT INTO scans (host_row, received_at, scan_id, started_at, schema_version, tool_version, digest, doc, pubkey, signature, packs, image_ref, image_digest) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT (host_row, scan_id) DO NOTHING`,
		hostRow, received, res.Scan.ID, res.Scan.StartedAt, res.SchemaVersion, res.Scan.Tool.Version, digest, gz.Bytes(), in.key, in.sig, packsJSON(res.Scan.Packs), imageRef, imageDigest)
	if err != nil {
		return nil, err
	}
	if n, err := r.RowsAffected(); err != nil {
		return nil, err
	} else if n == 0 {
		// Received before: the same document is a retry (acknowledged, not stored again), another is a conflict.
		var rowID int64
		var storedDigest, storedAt string
		if err := tx.QueryRowContext(ctx, `SELECT id, digest, received_at FROM scans WHERE host_row = ? AND scan_id = ?`, hostRow, res.Scan.ID).Scan(&rowID, &storedDigest, &storedAt); err != nil {
			return nil, err
		}
		if storedDigest != digest {
			return nil, ErrDuplicate
		}
		return &IngestResult{ScanRow: rowID, HostRow: hostRow, ReceivedAt: storedAt, Digest: digest, Duplicate: true}, nil
	}
	scanRow, err := r.LastInsertId()
	if err != nil {
		return nil, err
	}
	// What the list shows of the host comes from the result just stored, not from a retry of an older one (which
	// returned above).
	osName, labels := hostInfo(res)
	if _, err := tx.ExecContext(ctx, `UPDATE hosts SET os = ?, labels = ? WHERE id = ?`, osName, labels, hostRow); err != nil {
		return nil, err
	}
	insControl, err := tx.PrepareContext(ctx, `INSERT INTO scan_controls (scan_row, profile, control_id, severity, status, title) VALUES (?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return nil, err
	}
	defer insControl.Close()
	for _, c := range res.Controls {
		if _, err := insControl.ExecContext(ctx, scanRow, c.Profile, c.ID, string(c.Severity), string(c.Status), truncate(c.Title, 200)); err != nil {
			return nil, err
		}
	}
	insCheck, err := tx.PrepareContext(ctx, `INSERT INTO scan_checks (scan_row, ref, severity, status) VALUES (?, ?, ?, ?)`)
	if err != nil {
		return nil, err
	}
	defer insCheck.Close()
	for _, c := range res.Checks {
		// Passing checks can be read from the stored document; the rows are for what needs a look.
		if c.Status == engine.StatusPass || c.Status == engine.StatusNotApplicable {
			continue
		}
		if _, err := insCheck.ExecContext(ctx, scanRow, c.Ref, string(c.Severity), string(c.Status)); err != nil {
			return nil, err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE hosts SET last_scan_at = ? WHERE id = ?`, received, hostRow); err != nil {
		return nil, err
	}
	// A host that signs does not go back in time: a signed result older than the latest scan of the
	// host is a replay of one captured earlier (the scan ID alone would be accepted again after the
	// original was pruned).
	if in.key != "" {
		cur, err := time.Parse(time.RFC3339, res.Scan.StartedAt)
		if err != nil {
			return nil, fmt.Errorf("%w: the scan start time is not RFC 3339", ErrIdentity)
		}
		// Compared as instants (stored values may carry different offsets); one that cannot be read
		// refuses the result rather than skipping the check.
		rs, err := tx.QueryContext(ctx, `SELECT started_at FROM scans WHERE host_row = ? AND id != ?`, hostRow, scanRow)
		if err != nil {
			return nil, err
		}
		var latest time.Time
		for rs.Next() {
			var v string
			if err := rs.Scan(&v); err != nil {
				_ = rs.Close()
				return nil, err
			}
			t, err := time.Parse(time.RFC3339, v)
			if err != nil {
				_ = rs.Close()
				return nil, fmt.Errorf("%w: a stored scan has an unreadable start time", ErrIdentity)
			}
			if t.After(latest) {
				latest = t
			}
		}
		if err := rs.Err(); err != nil {
			_ = rs.Close()
			return nil, err
		}
		_ = rs.Close()
		if !latest.IsZero() && !cur.After(latest) {
			return nil, fmt.Errorf("%w: a signed result must be newer than the host's latest scan (started %s)", ErrIdentity, latest.UTC().Format(time.RFC3339))
		}
	}
	if err := appendAuditKey(ctx, tx, received, cred.ID, remote, "ingest", fmt.Sprintf("host %s scan %s", name, res.Scan.ID), digest, signing.Fingerprint(in.key)); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &IngestResult{ScanRow: scanRow, HostRow: hostRow, ReceivedAt: received, Digest: digest}, nil
}

// Audit records an event that is not an ingest (a rejected request, a token created).
func (s *Store) Audit(ctx context.Context, credentialID int64, remote, action, detail string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := appendAudit(ctx, tx, s.stamp(), credentialID, remote, action, detail); err != nil {
		return err
	}
	return tx.Commit()
}

const genesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// auditHash chains an audit row to the one before it.
func auditHash(prev, at string, credentialID int64, remote, action, detail, digest, key string) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\n%s\n%d\n%s\n%s\n%s\n%s", prev, at, credentialID, remote, action, detail, digest)
	if key != "" { // rows without a key hash as they always did
		fmt.Fprintf(h, "\n%s", key)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func appendAudit(ctx context.Context, tx *sql.Tx, at string, credentialID int64, remote, action, detail string) error {
	return appendAuditKey(ctx, tx, at, credentialID, remote, action, detail, "", "")
}

// appendAuditKey also records the fingerprint of the key a result was signed with: the chain then
// vouches for whether a stored scan was signed, and with what.
func appendAuditKey(ctx context.Context, tx *sql.Tx, at string, credentialID int64, remote, action, detail, digest, key string) error {
	prev := genesisHash
	err := tx.QueryRowContext(ctx, `SELECT hash FROM audit ORDER BY seq DESC LIMIT 1`).Scan(&prev)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	// Text from a result or a request is bounded before it is kept.
	detail = truncate(detail, 512)
	remote = truncate(remote, 128)
	_, err = tx.ExecContext(ctx, `INSERT INTO audit (at, credential_id, remote, action, detail, digest, key, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		at, credentialID, remote, action, detail, digest, key, prev, auditHash(prev, at, credentialID, remote, action, detail, digest, key))
	return err
}

// truncate cuts s to at most n bytes without splitting a character.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// VerifyAudit checks the hash chain of the audit table and returns the hash of the last
// row (to keep elsewhere: a changed or removed row breaks the chain from there on).
func (s *Store) VerifyAudit(ctx context.Context) (rows int, last string, err error) {
	rs, err := s.db.QueryContext(ctx, `SELECT seq, at, credential_id, remote, action, detail, digest, key, prev_hash, hash FROM audit ORDER BY seq`)
	if err != nil {
		return 0, "", err
	}
	defer rs.Close()
	prev := genesisHash
	for rs.Next() {
		var seq, cred int64
		var at, remote, action, detail, digest, key, prevHash, hash string
		if err := rs.Scan(&seq, &at, &cred, &remote, &action, &detail, &digest, &key, &prevHash, &hash); err != nil {
			return rows, prev, err
		}
		if prevHash != prev || hash != auditHash(prev, at, cred, remote, action, detail, digest, key) {
			return rows, prev, fmt.Errorf("the audit chain breaks at row %d", seq)
		}
		prev = hash
		rows++
	}
	return rows, prev, rs.Err()
}

// maxLabels and the lengths bound what a result may put in the host list: it is shown on every page.
const (
	maxLabels     = 10
	maxLabelKey   = 32
	maxLabelValue = 64
	maxOSName     = 100
)

// hostInfo is the operating system name and the labels (as JSON) the host list keeps of a result: bounded, and
// only printable text, so what a host says about itself cannot break the page that shows it.
func hostInfo(res *engine.Result) (osName, labels string) {
	osName = strings.TrimSpace(res.Host.OS.Name)
	if !plainText(osName) { // a name with a stray control character falls back to the ID and version
		osName = ""
	}
	if osName == "" {
		osName = strings.TrimSpace(res.Host.OS.ID + " " + res.Host.OS.VersionID)
		if !plainText(osName) {
			osName = ""
		}
	}
	osName = truncate(osName, maxOSName)
	keys := make([]string, 0, len(res.Host.Labels))
	for k := range res.Host.Labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	kept := map[string]string{}
	for _, k := range keys {
		v := res.Host.Labels[k]
		if len(kept) == maxLabels {
			break
		}
		if k == "" || strings.Contains(k, "=") || len(k) > maxLabelKey || len(v) > maxLabelValue || !plainText(k) || !plainText(v) {
			continue
		}
		kept[k] = v
	}
	if len(kept) == 0 {
		return osName, ""
	}
	b, err := json.Marshal(kept)
	if err != nil {
		return osName, ""
	}
	return osName, string(b)
}

// plainText is valid UTF-8 with no control characters and no format characters (the right-to-left override and the
// zero-width ones among them): text a host chose that the list shows beside names the reader trusts.
func plainText(s string) bool {
	return utf8.ValidString(s) && !strings.ContainsFunc(s, func(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) })
}

// packsJSON is the packs a result names, as the scans table keeps them ("" for none); checkLimits has bounded them.
func packsJSON(packs []engine.PackInfo) string {
	if len(packs) == 0 {
		return ""
	}
	b, err := json.Marshal(packs)
	if err != nil {
		return ""
	}
	return string(b)
}
