-- Migration 004: Unified scan_results table + domain_queue
-- SwarmHawk Global Domain Security Pipeline
-- Run once in Supabase SQL editor

-- ── scan_results: unified store for ALL domain scans (Tier 1 + Tier 2) ─────────
CREATE TABLE IF NOT EXISTS scan_results (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain           TEXT NOT NULL,
    tld              TEXT,                       -- last segment of domain (e.g. "com", "cz")
    country          TEXT,                       -- inferred from TLD or Cloudflare Radar
    risk_score       INTEGER DEFAULT 0,          -- unified 0-100 score
    critical         INTEGER DEFAULT 0,          -- Tier 2: count of critical check results
    warnings         INTEGER DEFAULT 0,          -- Tier 2: count of warning check results
    checks           JSONB DEFAULT '[]',         -- Tier 2: full 22-check results
    software         JSONB DEFAULT '[]',         -- detected software [{product, version}]
    cves             JSONB DEFAULT '[]',         -- CVEs found [{id, cvss, description}]
    max_cvss         NUMERIC(4,1) DEFAULT 0,     -- highest CVSS score across all CVEs
    scan_tier        INTEGER DEFAULT 1,          -- 1=passive (2 checks), 2=full (22 checks)
    source           TEXT DEFAULT 'unknown',     -- radar | umbrella | ct_logs | czds | user | manual
    contact_email    TEXT,
    contact_emails   JSONB DEFAULT '[]',
    priority         TEXT DEFAULT 'INFO',        -- CRITICAL | HIGH | MEDIUM | LOW | INFO
    -- Outreach workflow columns (NULL = not yet CVSS-qualified for outreach)
    outreach_status  TEXT,                       -- pending | approved | sent | rejected
    email_body       TEXT,
    edited           BOOLEAN DEFAULT FALSE,
    sent_to          TEXT,
    approved_at      TIMESTAMPTZ,
    sent_at          TIMESTAMPTZ,
    -- Ownership
    user_id          UUID,                       -- NULL for bulk/automated scans
    -- Scheduling
    last_scanned_at  TIMESTAMPTZ DEFAULT now(),
    next_scan_at     TIMESTAMPTZ DEFAULT now() + INTERVAL '7 days',
    created_at       TIMESTAMPTZ DEFAULT now(),
    CONSTRAINT scan_results_domain_unique UNIQUE (domain)
);

-- Indexes for common query patterns
CREATE INDEX IF NOT EXISTS scan_results_country_idx      ON scan_results (country);
CREATE INDEX IF NOT EXISTS scan_results_tld_idx          ON scan_results (tld);
CREATE INDEX IF NOT EXISTS scan_results_risk_idx         ON scan_results (risk_score DESC);
CREATE INDEX IF NOT EXISTS scan_results_next_scan_idx    ON scan_results (next_scan_at ASC);
CREATE INDEX IF NOT EXISTS scan_results_source_idx       ON scan_results (source);
CREATE INDEX IF NOT EXISTS scan_results_outreach_idx     ON scan_results (outreach_status)
    WHERE outreach_status IS NOT NULL;
CREATE INDEX IF NOT EXISTS scan_results_tier_idx         ON scan_results (scan_tier);
CREATE INDEX IF NOT EXISTS scan_results_cvss_idx         ON scan_results (max_cvss DESC);

-- ── domain_queue: domains pending their first Tier 1 scan ────────────────────
CREATE TABLE IF NOT EXISTS domain_queue (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain     TEXT NOT NULL,
    country    TEXT,
    source     TEXT DEFAULT 'unknown',
    priority   INTEGER DEFAULT 5,            -- 1=highest priority, 10=lowest
    tier       INTEGER DEFAULT 1,            -- scan tier requested
    queued_at  TIMESTAMPTZ DEFAULT now(),
    attempts   INTEGER DEFAULT 0,
    CONSTRAINT domain_queue_domain_unique UNIQUE (domain)
);

CREATE INDEX IF NOT EXISTS domain_queue_priority_idx ON domain_queue (priority ASC, queued_at ASC);
CREATE INDEX IF NOT EXISTS domain_queue_tier_idx     ON domain_queue (tier);
