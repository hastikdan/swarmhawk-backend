-- SwarmHawk Migration 003 — Domain Outreach Contacts
-- Paste into Supabase → SQL Editor → Run
-- Safe to run multiple times (IF NOT EXISTS everywhere)

-- ── domains table ──────────────────────────────────────────────────────────
ALTER TABLE domains ADD COLUMN IF NOT EXISTS primary_contact TEXT;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS contact_emails  TEXT;  -- JSON array of all contact emails

CREATE INDEX IF NOT EXISTS idx_domains_primary_contact
  ON domains(primary_contact) WHERE primary_contact IS NOT NULL;

-- Disable RLS so backend service role can read/write freely
ALTER TABLE domains DISABLE ROW LEVEL SECURITY;

-- ── outreach_prospects table ───────────────────────────────────────────────
ALTER TABLE outreach_prospects ADD COLUMN IF NOT EXISTS contact_email  TEXT;
ALTER TABLE outreach_prospects ADD COLUMN IF NOT EXISTS contact_emails TEXT;  -- JSON array

ALTER TABLE outreach_prospects DISABLE ROW LEVEL SECURITY;

SELECT 'Migration 003 complete — domain outreach contacts ready' AS status;
