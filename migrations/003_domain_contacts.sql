-- SwarmHawk Migration 003 — Domain Outreach Contacts
-- Paste into Supabase → SQL Editor → Run

-- Add outreach contact columns to domains table
ALTER TABLE domains ADD COLUMN IF NOT EXISTS primary_contact TEXT;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS contact_emails  TEXT;  -- JSON array of all discovered emails

-- Index for quick lookup of domains with a contact set
CREATE INDEX IF NOT EXISTS idx_domains_primary_contact ON domains(primary_contact)
  WHERE primary_contact IS NOT NULL;

ALTER TABLE domains DISABLE ROW LEVEL SECURITY;

SELECT 'Migration 003 complete — domain outreach contacts added' AS status;
