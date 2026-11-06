package server

import (
	"compress/flate"
	"compress/gzip"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
	"time"

	"github.com/with-developer/hostlint/internal/signing"
)

// pruneBatch is how many scans one delete removes, so the single writer is never held for long.
const pruneBatch = 200

// Prune deletes the scans received before now-olderThan, except the latest scan of every host: a
// host's last evidence is never removed, however old. The derived rows go with their scan. It returns how many
// scans were deleted and records the pruning in the audit table.
func (s *Store) Prune(ctx context.Context, olderThan time.Duration) (int, error) {
	if olderThan <= 0 {
		return 0, errors.New("the retention must be longer than zero")
	}
	cutoff := s.now().UTC().Add(-olderThan).Format(stampLayout)
	total := 0
	for {
		r, err := s.db.ExecContext(ctx, `
			DELETE FROM scans WHERE id IN (
				SELECT id FROM scans s
				WHERE received_at < ?
				  AND id != (SELECT id FROM scans WHERE host_row = s.host_row ORDER BY received_at DESC, id DESC LIMIT 1)
				LIMIT ?)`, cutoff, pruneBatch)
		if err != nil {
			return total, err
		}
		n, err := r.RowsAffected()
		if err != nil {
			return total, err
		}
		total += int(n)
		if n < pruneBatch {
			break
		}
		select {
		case <-ctx.Done():
			return total, ctx.Err()
		default:
		}
	}
	if total > 0 {
		if err := s.Audit(ctx, 0, "maintenance", "prune", fmt.Sprintf("%d scans received before %s", total, cutoff)); err != nil {
			return total, err
		}
	}
	return total, nil
}

// Backup writes a consistent copy of the database to path, which must not exist, with mode 0600.
// It uses SQLite's VACUUM INTO, which is safe while the server is running.
func (s *Store) Backup(ctx context.Context, path string) error {
	if strings.ContainsRune(path, 0) {
		return errors.New("not a file name")
	}
	// The file is created private first (SQLite copies into an empty file), so it is never
	// readable by others, not even for a moment; an existing file is not overwritten.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) //nolint:forbidigo,gosec // the server's own backup file (G304: the operator's path)
	if errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("%s exists: a backup does not overwrite", path)
	}
	if err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `VACUUM INTO ?`, path); err != nil {
		_ = os.Remove(path) //nolint:forbidigo // the empty file this call made
		return err
	}
	return nil
}

// Stats counts what the database holds, for `hostlint server stats`.
type Stats struct {
	Hosts, Scans, Credentials int
	Oldest, Newest            string
}

// Stats returns the counts of hosts, scans and tokens and the time range of the scans.
func (s *Store) Stats(ctx context.Context) (Stats, error) {
	var st Stats
	var oldest, newest sql.NullString
	err := s.db.QueryRowContext(ctx, `
		SELECT (SELECT COUNT(*) FROM hosts), (SELECT COUNT(*) FROM scans), (SELECT COUNT(*) FROM credentials WHERE revoked_at IS NULL),
		       (SELECT MIN(received_at) FROM scans), (SELECT MAX(received_at) FROM scans)`).Scan(&st.Hosts, &st.Scans, &st.Credentials, &oldest, &newest)
	st.Oldest, st.Newest = oldest.String, newest.String
	return st, err
}

// DeleteHost removes a host and everything received from it (its scans, with the rows derived from
// them). It is how an operator lets a re-installed machine, whose host ID changed, start again under
// the same name. The deletion is audited. It reports whether there was such a host.
func (s *Store) DeleteHost(ctx context.Context, id int64) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	var name string
	var scans int
	err = tx.QueryRowContext(ctx, `SELECT name, (SELECT COUNT(*) FROM scans WHERE host_row = hosts.id) FROM hosts WHERE id = ?`, id).Scan(&name, &scans)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM hosts WHERE id = ?`, id); err != nil {
		return false, err
	}
	if err := appendAudit(ctx, tx, s.stamp(), 0, "cli", "host-deleted", fmt.Sprintf("host %d %s with %d scans", id, name, scans), ""); err != nil {
		return false, err
	}
	return true, tx.Commit()
}

// Hosts of the database as `hostlint server host list` shows them.
func (s *Store) HostList(ctx context.Context) ([]HostSummary, error) {
	return s.allHosts(ctx, "", 0, 0)
}

// SignatureReport is what VerifySignatures found.
type SignatureReport struct {
	Signed, Unsigned int
	// Mismatched are the signed scans whose stored document does not match its signature.
	Mismatched []int64
	// Downgraded are the unsigned scans received after the host's first signed one: a host that
	// signs does not stop, so a scan without a signature there was stored without one or had it removed.
	Downgraded []int64
}

// OK reports whether every stored signature verifies and no host went back to unsigned.
func (r SignatureReport) OK() bool { return len(r.Mismatched) == 0 && len(r.Downgraded) == 0 }

// VerifySignatures checks every stored signed scan against the signature and key it arrived with: a
// document changed in the database afterwards does not verify. A database error is an error, not a
// finding; a stored document that cannot be read back (corrupt) is a mismatch.
func (s *Store) VerifySignatures(ctx context.Context) (SignatureReport, error) {
	var rep SignatureReport
	rs, err := s.db.QueryContext(ctx, `SELECT id, host_row, pubkey, signature FROM scans ORDER BY id`)
	if err != nil {
		return rep, err
	}
	type row struct {
		id, host int64
		key, sig string
	}
	var rows []row
	for rs.Next() {
		var r row
		if err := rs.Scan(&r.id, &r.host, &r.key, &r.sig); err != nil {
			_ = rs.Close()
			return rep, err
		}
		rows = append(rows, r)
	}
	if err := rs.Err(); err != nil {
		return rep, err
	}
	_ = rs.Close()
	firstSigned := map[int64]int64{} // host → id of its first signed scan
	for _, r := range rows {
		if r.sig != "" && firstSigned[r.host] == 0 {
			firstSigned[r.host] = r.id
		}
	}
	for _, r := range rows {
		if r.sig == "" {
			rep.Unsigned++
			if first := firstSigned[r.host]; first != 0 && r.id > first {
				rep.Downgraded = append(rep.Downgraded, r.id)
			}
			continue
		}
		rep.Signed++
		doc, err := s.ScanDoc(ctx, r.id)
		var corrupt flate.CorruptInputError
		switch {
		case errors.Is(err, gzip.ErrHeader), errors.Is(err, gzip.ErrChecksum), errors.Is(err, io.ErrUnexpectedEOF), errors.As(err, &corrupt):
			rep.Mismatched = append(rep.Mismatched, r.id)
		case err != nil:
			return rep, fmt.Errorf("scan %d: %w", r.id, err)
		case signing.Verify(r.key, r.sig, doc) != nil:
			rep.Mismatched = append(rep.Mismatched, r.id)
		}
	}
	return rep, nil
}

// ResetHostKey replaces the key registered for a host. newKey "" forgets it, so that the next signed
// result registers one (and until then unsigned results are accepted: prefer giving the new key). It
// is audited and reports whether the host had a key.
func (s *Store) ResetHostKey(ctx context.Context, id int64, newKey string) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	var name, key string
	err = tx.QueryRowContext(ctx, `SELECT name, pubkey FROM hosts WHERE id = ?`, id).Scan(&name, &key)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && key == "") {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if newKey != "" && signing.Fingerprint(newKey) == "" {
		return false, errors.New("the new key is not an Ed25519 public key in base64")
	}
	if _, err := tx.ExecContext(ctx, `UPDATE hosts SET pubkey = ? WHERE id = ?`, newKey, id); err != nil {
		return false, err
	}
	detail := fmt.Sprintf("host %d %s, key %s forgotten", id, name, signing.Fingerprint(key))
	if newKey != "" {
		detail = fmt.Sprintf("host %d %s, key %s replaced by %s", id, name, signing.Fingerprint(key), signing.Fingerprint(newKey))
	}
	if err := appendAudit(ctx, tx, s.stamp(), 0, "cli", "host-key-reset", detail, ""); err != nil {
		return false, err
	}
	return true, tx.Commit()
}
