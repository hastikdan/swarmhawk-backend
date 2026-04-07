-- SwarmHawk Migration 009 — Industry tag on domains
-- Paste into Supabase → SQL Editor → Run
-- Safe to run multiple times (IF NOT EXISTS)

-- Add industry column to domains so users can tag their domains with an industry sector.
-- The frontend auto-detects from domain name / CMS and the user can override via the badge.
ALTER TABLE domains ADD COLUMN IF NOT EXISTS industry TEXT;

CREATE INDEX IF NOT EXISTS idx_domains_industry ON domains (industry) WHERE industry IS NOT NULL;

SELECT 'Migration 009 complete — domains.industry column ready' AS status;
