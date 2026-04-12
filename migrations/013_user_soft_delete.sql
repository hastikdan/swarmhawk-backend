-- SwarmHawk Migration 013: soft-delete column for users
-- Paste into Supabase → SQL Editor → Run

ALTER TABLE users ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_users_deleted ON users (deleted_at) WHERE deleted_at IS NOT NULL;

SELECT 'Migration 013 complete — users.deleted_at column ready' AS status;
