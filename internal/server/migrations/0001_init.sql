-- The fleet server's schema (ADR 0010). Statements end with a line holding only ";;".

CREATE TABLE hosts (
  id           INTEGER PRIMARY KEY,
  name         TEXT NOT NULL,
  host_id      TEXT NOT NULL DEFAULT '',
  created_at   TEXT NOT NULL,
  last_scan_at TEXT,
  UNIQUE (name, host_id)
);
;;
CREATE TABLE credentials (
  id           INTEGER PRIMARY KEY,
  kind         TEXT NOT NULL CHECK (kind IN ('token')),
  scope        TEXT NOT NULL CHECK (scope IN ('ingest', 'api')),
  name         TEXT NOT NULL,
  prefix       TEXT NOT NULL,
  hash         TEXT NOT NULL UNIQUE,
  bound_name   TEXT,
  bound_host_id TEXT,
  created_at   TEXT NOT NULL,
  last_used_at TEXT,
  expires_at   TEXT,
  revoked_at   TEXT
);
;;
CREATE TABLE scans (
  id             INTEGER PRIMARY KEY,
  host_row       INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  received_at    TEXT NOT NULL,
  scan_id        TEXT NOT NULL,
  started_at     TEXT NOT NULL,
  schema_version INTEGER NOT NULL,
  tool_version   TEXT NOT NULL,
  digest         TEXT NOT NULL,
  doc            BLOB NOT NULL,
  UNIQUE (host_row, scan_id)
);
;;
CREATE INDEX scans_by_host ON scans (host_row, received_at);
;;
CREATE TABLE scan_controls (
  scan_row   INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  profile    TEXT NOT NULL,
  control_id TEXT NOT NULL,
  severity   TEXT NOT NULL,
  status     TEXT NOT NULL,
  PRIMARY KEY (scan_row, profile, control_id)
);
;;
CREATE TABLE scan_checks (
  scan_row INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  ref      TEXT NOT NULL,
  severity TEXT NOT NULL,
  status   TEXT NOT NULL,
  PRIMARY KEY (scan_row, ref)
);
;;
CREATE TABLE audit (
  seq           INTEGER PRIMARY KEY,
  at            TEXT NOT NULL,
  credential_id INTEGER,
  remote        TEXT NOT NULL,
  action        TEXT NOT NULL,
  detail        TEXT NOT NULL,
  digest        TEXT NOT NULL DEFAULT '',
  prev_hash     TEXT NOT NULL,
  hash          TEXT NOT NULL
);
