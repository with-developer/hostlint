package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Scopes of a credential.
const (
	ScopeIngest = "ingest" // may submit scan results
	ScopeAPI    = "api"    // may read (later changes)
)

var scopePrefix = map[string]string{ScopeIngest: "hlt_ing_", ScopeAPI: "hlt_api_"}

// Credential is a token known to the server. Only its hash is stored.
type Credential struct {
	ID          int64
	Scope       string
	Name        string
	Prefix      string
	BoundName   string // the host name it may speak for; "" for any host
	BoundHostID string // pinned at its first use
	CreatedAt   string
	LastUsedAt  string
	ExpiresAt   string
	RevokedAt   string
}

// ErrUnauthorized means the token is unknown, revoked, expired or of the wrong scope.
var ErrUnauthorized = errors.New("unauthorized")

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// CreateCredential makes a token and returns it: it is the only time it can be seen.
// boundName "" lets the token speak for any host (an explicit opt-in).
func (s *Store) CreateCredential(ctx context.Context, scope, name, boundName string, expires time.Duration) (token string, id int64, err error) {
	prefix, ok := scopePrefix[scope]
	if !ok {
		return "", 0, fmt.Errorf("unknown scope %q", scope)
	}
	if strings.TrimSpace(name) == "" {
		return "", 0, errors.New("a token needs a name")
	}
	var secret [32]byte // 256 bits
	if _, err := rand.Read(secret[:]); err != nil {
		return "", 0, err
	}
	token = prefix + base64.RawURLEncoding.EncodeToString(secret[:])
	var expiresAt any
	if expires > 0 {
		expiresAt = s.now().UTC().Add(expires).Format(time.RFC3339)
	}
	var bound any
	if boundName != "" {
		bound = boundName
	}
	// The token and its audit row are one transaction: no credential exists without its record.
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = tx.Rollback() }()
	at := s.stamp()
	r, err := tx.ExecContext(ctx,
		`INSERT INTO credentials (kind, scope, name, prefix, hash, bound_name, created_at, expires_at) VALUES ('token', ?, ?, ?, ?, ?, ?, ?)`,
		scope, name, token[:len(prefix)+4], hashToken(token), bound, at, expiresAt)
	if err != nil {
		return "", 0, err
	}
	id, err = r.LastInsertId()
	if err != nil {
		return "", 0, err
	}
	if err := appendAudit(ctx, tx, at, id, "cli", "token-created", fmt.Sprintf("%s token %q for %s", scope, truncate(name, 100), orAny(boundName)), ""); err != nil {
		return "", 0, err
	}
	if err := tx.Commit(); err != nil {
		return "", 0, err
	}
	return token, id, nil
}

func orAny(name string) string {
	if name == "" {
		return "any host"
	}
	return "host " + name
}

// Authenticate finds the credential a token belongs to and records its use.
func (s *Store) Authenticate(ctx context.Context, token, scope string) (*Credential, error) {
	prefix := scopePrefix[scope]
	if prefix == "" || !strings.HasPrefix(token, prefix) || len(token) > 128 {
		return nil, ErrUnauthorized
	}
	var c Credential
	var bound, boundID, last, expires, revoked sql.NullString
	err := s.db.QueryRowContext(ctx,
		`SELECT id, scope, name, prefix, bound_name, bound_host_id, created_at, last_used_at, expires_at, revoked_at FROM credentials WHERE hash = ?`,
		hashToken(token)).Scan(&c.ID, &c.Scope, &c.Name, &c.Prefix, &bound, &boundID, &c.CreatedAt, &last, &expires, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUnauthorized
	}
	if err != nil {
		return nil, err
	}
	c.BoundName, c.BoundHostID, c.LastUsedAt, c.ExpiresAt, c.RevokedAt = bound.String, boundID.String, last.String, expires.String, revoked.String
	if !s.usable(&c, scope) {
		return nil, ErrUnauthorized
	}
	if err := s.touch(ctx, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// usable is the one place that decides whether a credential may be used now: its scope, that it
// is not revoked and that it has not expired. A token and a session opened with it both ask.
func (s *Store) usable(c *Credential, scope string) bool {
	if c.Scope != scope || c.RevokedAt != "" {
		return false
	}
	if c.ExpiresAt != "" {
		if t, err := time.Parse(time.RFC3339, c.ExpiresAt); err != nil || !s.now().Before(t) {
			return false
		}
	}
	return true
}

// touch records that a credential was used. That is a write: once a minute is enough for "last
// used", and a read does not wait for the database's writer on every request.
func (s *Store) touch(ctx context.Context, c *Credential) error {
	if last, err := time.Parse(stampLayout, c.LastUsedAt); err == nil && s.now().Sub(last) <= time.Minute {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `UPDATE credentials SET last_used_at = ? WHERE id = ?`, s.stamp(), c.ID)
	return err
}

// ListCredentials returns every credential, newest first. Hashes are never returned.
func (s *Store) ListCredentials(ctx context.Context) ([]Credential, error) {
	rs, err := s.db.QueryContext(ctx,
		`SELECT id, scope, name, prefix, bound_name, bound_host_id, created_at, last_used_at, expires_at, revoked_at FROM credentials ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	var out []Credential
	for rs.Next() {
		var c Credential
		var bound, boundID, last, expires, revoked sql.NullString
		if err := rs.Scan(&c.ID, &c.Scope, &c.Name, &c.Prefix, &bound, &boundID, &c.CreatedAt, &last, &expires, &revoked); err != nil {
			return nil, err
		}
		c.BoundName, c.BoundHostID, c.LastUsedAt, c.ExpiresAt, c.RevokedAt = bound.String, boundID.String, last.String, expires.String, revoked.String
		out = append(out, c)
	}
	return out, rs.Err()
}

// RevokeCredential revokes a token. It reports whether there was one to revoke.
func (s *Store) RevokeCredential(ctx context.Context, id int64) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	at := s.stamp()
	r, err := tx.ExecContext(ctx, `UPDATE credentials SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`, at, id)
	if err != nil {
		return false, err
	}
	n, err := r.RowsAffected()
	if err != nil || n == 0 {
		return false, err
	}
	if err := appendAudit(ctx, tx, at, id, "cli", "token-revoked", fmt.Sprintf("token %d", id), ""); err != nil {
		return false, err
	}
	return true, tx.Commit()
}
