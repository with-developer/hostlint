package server

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/with-developer/vmsctl/internal/output"
	"github.com/with-developer/vmsctl/internal/signing"
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

// Stats counts what the database holds, for `vmsctl server stats`.
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
	if _, err := tx.ExecContext(ctx, `DELETE FROM notify_state WHERE name = ?`, "silent-"+strconv.FormatInt(id, 10)); err != nil {
		return false, err
	}
	if err := appendAudit(ctx, tx, s.stamp(), 0, "cli", "host-deleted", fmt.Sprintf("host %d %s with %d scans", id, name, scans)); err != nil {
		return false, err
	}
	return true, tx.Commit()
}

// Hosts of the database as `vmsctl server host list` shows them.
func (s *Store) HostList(ctx context.Context) ([]HostSummary, error) {
	return s.allHosts(ctx, "", 0, kindAny, 0, "")
}

// SignatureReport is what VerifySignatures found.
type SignatureReport struct {
	Signed, Unsigned int
	// Mismatched are the scans whose stored document, signature or key does not match what the audit chain
	// recorded when they were received: a changed document, a removed or replaced signature.
	Mismatched []int64
	// Derived are the scans whose host or control statuses, as the dashboard shows them, differ from the stored
	// document (the individual check rows are not compared).
	Derived []int64
	// Unrecorded are the scans that no ingest audit row accounts for (not received through the server).
	Unrecorded []int64
}

// OK reports whether every check passed.
func (r SignatureReport) OK() bool {
	return len(r.Mismatched)+len(r.Derived)+len(r.Unrecorded) == 0
}

// VerifySignatures checks every stored scan against what the hash-chained audit table recorded at its
// ingest (the digest of the document and the key it was signed with), against its signature, and
// against the rows derived from it. Whoever changes a stored document, strips or replaces its signature,
// moves a scan to another host or edits what the dashboard shows has to rewrite the audit chain too,
// which the hash kept elsewhere ("vmsctl server verify" prints it) exposes. A database error is an
// error, not a finding; a document that cannot be read back (corrupt) is a mismatch.
func (s *Store) VerifySignatures(ctx context.Context) (SignatureReport, error) {
	var rep SignatureReport
	// A document can be received more than once (after a host was deleted, say): every ingest of a
	// digest is kept, and a stored scan has to match one of them.
	recorded := map[string][]string{} // digest of a document → the key fingerprints its ingests recorded
	ar, err := s.db.QueryContext(ctx, `SELECT digest, key FROM audit WHERE action = 'ingest'`)
	if err != nil {
		return rep, err
	}
	for ar.Next() {
		var digest, key string
		if err := ar.Scan(&digest, &key); err != nil {
			_ = ar.Close()
			return rep, err
		}
		recorded[digest] = append(recorded[digest], key)
	}
	if err := ar.Err(); err != nil {
		return rep, err
	}
	_ = ar.Close()

	rs, err := s.db.QueryContext(ctx, `SELECT s.id, s.host_row, s.digest, s.pubkey, s.signature, h.name, h.host_id FROM scans s JOIN hosts h ON h.id = s.host_row ORDER BY s.id`)
	if err != nil {
		return rep, err
	}
	type row struct {
		id, host                    int64
		digest, key, sig, name, hid string
	}
	var rows []row
	for rs.Next() {
		var r row
		if err := rs.Scan(&r.id, &r.host, &r.digest, &r.key, &r.sig, &r.name, &r.hid); err != nil {
			_ = rs.Close()
			return rep, err
		}
		rows = append(rows, r)
	}
	if err := rs.Err(); err != nil {
		return rep, err
	}
	_ = rs.Close()
	for _, r := range rows {
		if r.sig == "" {
			rep.Unsigned++
		} else {
			rep.Signed++
		}
		keys, ok := recorded[r.digest]
		if !ok {
			rep.Unrecorded = append(rep.Unrecorded, r.id)
			continue
		}
		doc, err := s.ScanDoc(ctx, r.id)
		var corrupt flate.CorruptInputError
		switch {
		case errors.Is(err, gzip.ErrHeader), errors.Is(err, gzip.ErrChecksum), errors.Is(err, io.ErrUnexpectedEOF), errors.As(err, &corrupt):
			rep.Mismatched = append(rep.Mismatched, r.id)
			continue
		case err != nil:
			return rep, fmt.Errorf("scan %d: %w", r.id, err)
		}
		sum := sha256.Sum256(doc)
		switch {
		case "sha256:"+hex.EncodeToString(sum[:]) != r.digest,
			!slices.Contains(keys, signing.Fingerprint(r.key)), // "" for an unsigned scan, as the ingest recorded it
			r.sig != "" && signing.Verify(r.key, r.sig, doc) != nil:
			rep.Mismatched = append(rep.Mismatched, r.id)
			continue
		}
		if !s.derivedMatches(ctx, r.id, r.name, r.hid, doc) {
			rep.Derived = append(rep.Derived, r.id)
		}
	}
	return rep, nil
}

// derivedMatches reports whether the controls stored for a scan, and the host it is filed under, are
// what its document says.
func (s *Store) derivedMatches(ctx context.Context, scanRow int64, name, hostID string, doc []byte) bool {
	res, err := output.ReadResult(bytes.NewReader(doc))
	if err != nil || res.Host.Hostname != name || res.Host.HostID != hostID {
		return false
	}
	rs, err := s.db.QueryContext(ctx, `SELECT profile, control_id, status FROM scan_controls WHERE scan_row = ?`, scanRow)
	if err != nil {
		return false
	}
	defer rs.Close()
	got := map[string]string{}
	for rs.Next() {
		var p, id, st string
		if err := rs.Scan(&p, &id, &st); err != nil {
			return false
		}
		got[p+"\x00"+id] = st
	}
	if rs.Err() != nil || len(got) != len(res.Controls) {
		return false
	}
	for _, c := range res.Controls {
		if got[c.Profile+"\x00"+c.ID] != string(c.Status) {
			return false
		}
	}
	return true
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
	if err := appendAudit(ctx, tx, s.stamp(), 0, "cli", "host-key-reset", detail); err != nil {
		return false, err
	}
	return true, tx.Commit()
}
