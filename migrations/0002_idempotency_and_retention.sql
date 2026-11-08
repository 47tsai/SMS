-- Phase 1 (P0): idempotency key for ingest dedup + 30-day retention.
-- idempotency_key is SHA-256(sender || message || receivedAt), computed by
-- the Worker. SQLite treats NULLs as distinct in a UNIQUE index, so rows
-- created before this migration (idempotency_key NULL) do not conflict.
-- expires_at is set at insert time (UTC, now + 30 days). Rows created before
-- this migration have expires_at NULL; the scheduled cleanup falls back to
-- created_at for those rows (see scheduled() in src/index.js).
ALTER TABLE messages ADD COLUMN idempotency_key TEXT;
ALTER TABLE messages ADD COLUMN expires_at TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS idx_messages_idempotency_key ON messages(idempotency_key);
CREATE INDEX IF NOT EXISTS idx_messages_expires_at ON messages(expires_at);
