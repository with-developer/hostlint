package server

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
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

// VerifySignatures checks every stored signed scan: the document in the database against the
// signature and key it arrived with. A document changed after it was stored does not verify.
// It returns how many signed and unsigned scans there are and the scans that failed.
func (s *Store) VerifySignatures(ctx context.Context) (signed, unsigned int, failed []int64, err error) {
	rs, err := s.db.QueryContext(ctx, `SELECT id, pubkey, signature FROM scans ORDER BY id`)
	if err != nil {
		return 0, 0, nil, err
	}
	type row struct {
		id       int64
		key, sig string
	}
	var rows []row
	for rs.Next() {
		var r row
		if err := rs.Scan(&r.id, &r.key, &r.sig); err != nil {
			_ = rs.Close()
			return 0, 0, nil, err
		}
		rows = append(rows, r)
	}
	if err := rs.Err(); err != nil {
		return 0, 0, nil, err
	}
	_ = rs.Close()
	for _, r := range rows {
		if r.sig == "" {
			unsigned++
			continue
		}
		signed++
		doc, err := s.ScanDoc(ctx, r.id)
		if err != nil || signing.Verify(r.key, r.sig, doc) != nil {
			failed = append(failed, r.id)
		}
	}
	return signed, unsigned, failed, nil
}

// ResetHostKey forgets the key registered for a host, so its next signed result registers a new one
// (a re-installed machine with a new key). It is audited and reports whether the host had a key.
func (s *Store) ResetHostKey(ctx context.Context, id int64) (bool, error) {
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
	if _, err := tx.ExecContext(ctx, `UPDATE hosts SET pubkey = '' WHERE id = ?`, id); err != nil {
		return false, err
	}
	if err := appendAudit(ctx, tx, s.stamp(), 0, "cli", "host-key-reset", fmt.Sprintf("host %d %s, key %s", id, name, signing.Fingerprint(key)), ""); err != nil {
		return false, err
	}
	return true, tx.Commit()
}
