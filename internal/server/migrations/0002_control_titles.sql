-- The title of a control as the result carried it (bounded text, shown as text only).
ALTER TABLE scan_controls ADD COLUMN title TEXT NOT NULL DEFAULT '';
