package server

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"time"
)

// Session lifetimes: idle and absolute.
const (
	sessionIdle     = 8 * time.Hour
	sessionAbsolute = 24 * time.Hour
	// SessionCookie is the name of the session cookie.
	SessionCookie = "hl_session"
)

// CreateSession starts a session for a credential and returns the cookie value, which is not stored:
// only its hash is. Expired sessions are removed on the way.
func (s *Store) CreateSession(ctx context.Context, credentialID int64) (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	value := base64.RawURLEncoding.EncodeToString(raw[:])
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback() }()
	now := s.now().UTC()
	if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE created_at < ? OR last_seen_at < ?`,
		now.Add(-sessionAbsolute).Format(stampLayout), now.Add(-sessionIdle).Format(stampLayout)); err != nil {
		return "", err
	}
	at := now.Format(stampLayout)
	if _, err := tx.ExecContext(ctx, `INSERT INTO sessions (hash, credential_id, created_at, last_seen_at) VALUES (?, ?, ?, ?)`,
		hashToken(value), credentialID, at, at); err != nil {
		return "", err
	}
	return value, tx.Commit()
}

// AuthenticateSession returns the credential a session cookie belongs to. The session ends with
// its credential: a revoked or expired token also ends the dashboard sessions it opened.
func (s *Store) AuthenticateSession(ctx context.Context, value string) (*Credential, error) {
	if value == "" || len(value) > 128 {
		return nil, ErrUnauthorized
	}
	var c Credential
	var sid int64
	var created, seen string
	var bound, boundID, last, expires, revoked sql.NullString
	err := s.db.QueryRowContext(ctx, `
		SELECT s.id, s.created_at, s.last_seen_at, c.id, c.scope, c.name, c.prefix, c.bound_name, c.bound_host_id, c.created_at, c.last_used_at, c.expires_at, c.revoked_at
		FROM sessions s JOIN credentials c ON c.id = s.credential_id WHERE s.hash = ?`, hashToken(value)).
		Scan(&sid, &created, &seen, &c.ID, &c.Scope, &c.Name, &c.Prefix, &bound, &boundID, &c.CreatedAt, &last, &expires, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUnauthorized
	}
	if err != nil {
		return nil, err
	}
	c.BoundName, c.BoundHostID, c.LastUsedAt, c.ExpiresAt, c.RevokedAt = bound.String, boundID.String, last.String, expires.String, revoked.String
	now := s.now().UTC()
	createdAt, err1 := time.Parse(stampLayout, created)
	seenAt, err2 := time.Parse(stampLayout, seen)
	if err1 != nil || err2 != nil || now.Sub(createdAt) > sessionAbsolute || now.Sub(seenAt) > sessionIdle || c.Scope != ScopeAPI || c.RevokedAt != "" {
		return nil, ErrUnauthorized
	}
	if c.ExpiresAt != "" {
		if t, err := time.Parse(time.RFC3339, c.ExpiresAt); err != nil || !now.Before(t) {
			return nil, ErrUnauthorized
		}
	}
	if now.Sub(seenAt) > time.Minute {
		if _, err := s.db.ExecContext(ctx, `UPDATE sessions SET last_seen_at = ? WHERE id = ?`, s.stamp(), sid); err != nil {
			return nil, err
		}
	}
	return &c, nil
}

// DeleteSession ends a session.
func (s *Store) DeleteSession(ctx context.Context, value string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE hash = ?`, hashToken(value))
	return err
}
