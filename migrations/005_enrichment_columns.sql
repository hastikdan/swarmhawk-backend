-- Migration 005: Enrichment columns for scan_results
-- Run in Supabase SQL editor
-- Adds structured columns from Tier 1.5 fast enrichment
-- (email security, domain age, blacklist status, IP intel)

ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS spf_status      TEXT;
ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS dmarc_status     TEXT;
ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS dkim_status      TEXT;
ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS domain_age_days  INT;
ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS registrar        TEXT;
ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS blacklisted      BOOLEAN DEFAULT FALSE;
ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS blacklist_hits   JSONB   DEFAULT '[]';
ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS urlhaus_status   TEXT;
ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS ip_reputation    TEXT;
ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS waf_detected     BOOLEAN DEFAULT FALSE;

-- Indexes for common filter patterns
CREATE INDEX IF NOT EXISTS idx_scan_results_blacklisted   ON scan_results (blacklisted) WHERE blacklisted = TRUE;
CREATE INDEX IF NOT EXISTS idx_scan_results_dmarc_missing ON scan_results (dmarc_status) WHERE dmarc_status = 'missing';
CREATE INDEX IF NOT EXISTS idx_scan_results_domain_age    ON scan_results (domain_age_days);
CREATE INDEX IF NOT EXISTS idx_scan_results_spf_status    ON scan_results (spf_status);
