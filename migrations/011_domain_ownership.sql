-- SwarmHawk Migration 011 — Domain ownership verification + authenticated scan storage
-- Paste into Supabase → SQL Editor → Run
-- Safe to run multiple times (IF NOT EXISTS / DO NOTHING)

-- Domain ownership verification timestamp (on the domains table)
ALTER TABLE domains ADD COLUMN IF NOT EXISTS verified_at TIMESTAMPTZ;

-- Authenticated scan result stored alongside each regular scan
ALTER TABLE scans ADD COLUMN IF NOT EXISTS auth_scan    JSONB;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS auth_scanned_at TIMESTAMPTZ;

SELECT 'Migration 011 complete — domains.verified_at + scans.auth_scan ready' AS status;
