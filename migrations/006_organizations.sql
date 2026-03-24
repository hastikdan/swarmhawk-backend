-- Migration 006: Enterprise Organization Graph
-- SwarmHawk Enterprise EASM + Breach Path Engine
-- Run once in Supabase SQL editor

-- ── organizations: clustered domain groups mapped to real companies ───────────
CREATE TABLE IF NOT EXISTS organizations (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    registered_domain   TEXT NOT NULL,
    name                TEXT,                           -- inferred or manually set
    domain_count        INTEGER DEFAULT 0,
    org_risk_score      INTEGER DEFAULT 0,              -- 0-100 aggregate score
    entry_points        INTEGER DEFAULT 0,              -- domains with CVE/blacklist
    critical_assets     INTEGER DEFAULT 0,              -- domains with DAST/admin panels
    choke_points        INTEGER DEFAULT 0,              -- bottleneck nodes in attack graph
    attack_paths        INTEGER DEFAULT 0,              -- total enumerated breach paths
    asset_graph         JSONB DEFAULT '{}',             -- {nodes, edges, paths, choke_points, blast_radius, stats}
    country             TEXT,
    industry            TEXT,
    last_computed       TIMESTAMPTZ DEFAULT now(),
    created_at          TIMESTAMPTZ DEFAULT now(),
    CONSTRAINT organizations_registered_domain_unique UNIQUE (registered_domain)
);

CREATE INDEX IF NOT EXISTS idx_orgs_risk          ON organizations (org_risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_orgs_domain_count  ON organizations (domain_count DESC);
CREATE INDEX IF NOT EXISTS idx_orgs_entry_points  ON organizations (entry_points DESC);
CREATE INDEX IF NOT EXISTS idx_orgs_country       ON organizations (country);
CREATE INDEX IF NOT EXISTS idx_orgs_last_computed ON organizations (last_computed ASC);

-- ── Add registered_domain column to scan_results ──────────────────────────────
ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS registered_domain TEXT;
CREATE INDEX IF NOT EXISTS idx_scan_results_registered_domain ON scan_results (registered_domain);

-- ── org_compute_log: track clustering job runs ────────────────────────────────
CREATE TABLE IF NOT EXISTS org_compute_log (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    started_at      TIMESTAMPTZ DEFAULT now(),
    finished_at     TIMESTAMPTZ,
    orgs_created    INTEGER DEFAULT 0,
    orgs_updated    INTEGER DEFAULT 0,
    domains_tagged  INTEGER DEFAULT 0,
    total_processed INTEGER DEFAULT 0,
    status          TEXT DEFAULT 'running'  -- running | completed | failed
);
