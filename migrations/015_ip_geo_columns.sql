-- Migration 015: Ensure IP geo / datacenter enrichment columns exist on scan_results.
-- These columns are written by _geo_enrich_domains() in pipeline.py after each
-- Tier 1 batch. The ip_asn field (e.g. "AS24940 Hetzner Online GmbH") is the
-- primary key for the hosting-provider lookup in /gtm/hosting-matrix.
--
-- Safe to run multiple times (IF NOT EXISTS).

ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS ip_address  TEXT;
ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS ip_lat      FLOAT;
ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS ip_lon      FLOAT;
ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS ip_city     TEXT;
ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS ip_asn      TEXT;   -- "AS24940 Hetzner Online GmbH"
ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS ip_org      TEXT;   -- raw org name from ip-api.com

-- Index for the GTM hosting matrix query (filters on ip_asn IS NOT NULL)
CREATE INDEX IF NOT EXISTS idx_scan_results_ip_asn
    ON scan_results (ip_asn)
    WHERE ip_asn IS NOT NULL AND ip_asn <> '';

-- Index for the map endpoint (filters on ip_lat IS NOT NULL)
CREATE INDEX IF NOT EXISTS idx_scan_results_ip_lat
    ON scan_results (ip_lat)
    WHERE ip_lat IS NOT NULL;
