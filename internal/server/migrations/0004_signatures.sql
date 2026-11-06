-- Signed results (ADR 0010): the key a host signs with is registered at its first signed result.
ALTER TABLE hosts ADD COLUMN pubkey TEXT NOT NULL DEFAULT '';
;;
ALTER TABLE scans ADD COLUMN pubkey TEXT NOT NULL DEFAULT '';
;;
ALTER TABLE scans ADD COLUMN signature TEXT NOT NULL DEFAULT '';
