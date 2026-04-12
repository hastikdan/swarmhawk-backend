-- SwarmHawk Migration 014: kev_matched flag for scan_results
-- Replaces the inaccurate risk_score >= 95 proxy with an explicit boolean.
-- Paste into Supabase → SQL Editor → Run

ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS kev_matched BOOLEAN DEFAULT FALSE;

CREATE INDEX IF NOT EXISTS idx_scan_results_kev ON scan_results (kev_matched) WHERE kev_matched = TRUE;

SELECT 'Migration 014 complete — scan_results.kev_matched column ready' AS status;
