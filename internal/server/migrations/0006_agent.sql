-- The outbound agent (ADR 0014): what the server knows of a host's agent, and the one job it may be asked for.
-- A third scope, operator (reads, and asks agents for scans). A CHECK cannot be altered, so credentials is rebuilt;
-- sessions refers to it and is rebuilt around it, keeping its rows.
CREATE TABLE credentials_new (
  id           INTEGER PRIMARY KEY,
  kind         TEXT NOT NULL CHECK (kind IN ('token')),
  scope        TEXT NOT NULL CHECK (scope IN ('ingest', 'api', 'operator')),
  name         TEXT NOT NULL,
  prefix       TEXT NOT NULL,
  hash         TEXT NOT NULL UNIQUE,
  bound_name   TEXT,
  bound_host_id TEXT,
  created_at   TEXT NOT NULL,
  last_used_at TEXT,
  expires_at   TEXT,
  revoked_at   TEXT,
  pubkey       TEXT NOT NULL DEFAULT ''
);
;;
INSERT INTO credentials_new (id, kind, scope, name, prefix, hash, bound_name, bound_host_id, created_at, last_used_at, expires_at, revoked_at, pubkey)
  SELECT id, kind, scope, name, prefix, hash, bound_name, bound_host_id, created_at, last_used_at, expires_at, revoked_at, pubkey FROM credentials;
;;
CREATE TABLE sessions_new (
  id            INTEGER PRIMARY KEY,
  hash          TEXT NOT NULL UNIQUE,
  credential_id INTEGER NOT NULL REFERENCES credentials_new(id) ON DELETE CASCADE,
  created_at    TEXT NOT NULL,
  last_seen_at  TEXT NOT NULL
);
;;
INSERT INTO sessions_new (id, hash, credential_id, created_at, last_seen_at) SELECT id, hash, credential_id, created_at, last_seen_at FROM sessions;
;;
DROP TABLE sessions;
;;
DROP TABLE credentials;
;;
ALTER TABLE credentials_new RENAME TO credentials;
;;
ALTER TABLE sessions_new RENAME TO sessions;
;;
CREATE INDEX sessions_by_credential ON sessions (credential_id, created_at);
;;
CREATE INDEX sessions_by_seen ON sessions (last_seen_at);
;;
ALTER TABLE hosts ADD COLUMN agent_seen_at TEXT;
;;
ALTER TABLE hosts ADD COLUMN agent_profiles TEXT NOT NULL DEFAULT '';
;;
CREATE TABLE agent_jobs (
  id           INTEGER PRIMARY KEY,
  host_row     INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  profile      TEXT NOT NULL,
  requested_by INTEGER NOT NULL,
  created_at   TEXT NOT NULL,
  claimed_at   TEXT,
  finished_at  TEXT,
  state        TEXT NOT NULL,
  scan_row     INTEGER,
  error        TEXT NOT NULL DEFAULT ''
);
;;
CREATE INDEX agent_jobs_by_host ON agent_jobs (host_row, id);
