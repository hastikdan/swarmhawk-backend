-- SwarmHawk Migration 010 — User roles
-- Paste into Supabase → SQL Editor → Run
-- Safe to run multiple times (IF NOT EXISTS / DO NOTHING)

-- Add role column: 'user' (default) or 'admin'
ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'user';

CREATE INDEX IF NOT EXISTS idx_users_role ON users (role) WHERE role <> 'user';

SELECT 'Migration 010 complete — users.role column ready' AS status;
