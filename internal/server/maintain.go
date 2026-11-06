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
	if _, err := os.Stat(path); err == nil { //nolint:forbidigo // the server's own backup file, not the scanned host
		return fmt.Errorf("%s exists: a backup does not overwrite", path)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `VACUUM INTO ?`, path); err != nil {
		return err
	}
	return os.Chmod(path, 0o600) //nolint:forbidigo // the server's own backup file
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
