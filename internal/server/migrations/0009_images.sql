-- Container images as a second kind of asset (ADR 0016): a host row is a host or an image, and each scan of an image records
-- the reference and the image ID it was of.
ALTER TABLE hosts ADD COLUMN kind TEXT NOT NULL DEFAULT 'host';
;;
ALTER TABLE scans ADD COLUMN image_ref TEXT NOT NULL DEFAULT '';
;;
ALTER TABLE scans ADD COLUMN image_digest TEXT NOT NULL DEFAULT '';
