-- Dashboard sessions: a read token is exchanged once for a cookie (ADR 0010).
CREATE TABLE sessions (
  id            INTEGER PRIMARY KEY,
  hash          TEXT NOT NULL UNIQUE,
  credential_id INTEGER NOT NULL REFERENCES credentials(id) ON DELETE CASCADE,
  created_at    TEXT NOT NULL,
  last_seen_at  TEXT NOT NULL
);
