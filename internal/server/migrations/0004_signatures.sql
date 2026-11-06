-- Signed results (ADR 0010): the key a host signs with is registered at its first signed result.
ALTER TABLE hosts ADD COLUMN pubkey TEXT NOT NULL DEFAULT '';
;;
ALTER TABLE scans ADD COLUMN pubkey TEXT NOT NULL DEFAULT '';
;;
ALTER TABLE scans ADD COLUMN signature TEXT NOT NULL DEFAULT '';
;;
-- The fingerprint of the key a result was signed with, in the hash-chained audit row of its ingest.
ALTER TABLE audit ADD COLUMN key TEXT NOT NULL DEFAULT '';
;;
-- A token can be bound to the public key its host signs with: no trust on first use.
ALTER TABLE credentials ADD COLUMN pubkey TEXT NOT NULL DEFAULT '';
