-- What the webhook notifier has already reported (ADR 0010): a cursor over scans, and the last scan of a
-- host that was reported as silent.
CREATE TABLE notify_state (
  name  TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
