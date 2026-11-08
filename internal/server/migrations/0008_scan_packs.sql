-- The policy packs a scan names (ADR 0016), as JSON: kept apart from the stored document so a host's page does not
-- have to read the document for them.
ALTER TABLE scans ADD COLUMN packs TEXT NOT NULL DEFAULT '';
