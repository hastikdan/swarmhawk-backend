-- SwarmHawk TIER 1 Schema Migration
-- Paste into Supabase → SQL Editor → Run
-- (matches existing schema.sql conventions: no RLS, backend handles auth)

-- ── Purchases table: add missing columns ─────────────────────────────────────
ALTER TABLE purchases ADD COLUMN IF NOT EXISTS plan         TEXT DEFAULT 'one_time';
ALTER TABLE purchases ADD COLUMN IF NOT EXISTS domain       TEXT DEFAULT '';
ALTER TABLE purchases ADD COLUMN IF NOT EXISTS stripe_sub_id TEXT;
ALTER TABLE purchases ADD COLUMN IF NOT EXISTS cancelled_at TIMESTAMPTZ;
ALTER TABLE purchases ADD COLUMN IF NOT EXISTS paid_at      TIMESTAMPTZ DEFAULT now();

-- Index for fast subscription lookups
CREATE INDEX IF NOT EXISTS idx_purchases_user   ON purchases(user_id);
CREATE INDEX IF NOT EXISTS idx_purchases_domain ON purchases(domain_id);

ALTER TABLE purchases DISABLE ROW LEVEL SECURITY;

-- ── Outreach Prospects ───────────────────────────────────────────────────────
-- Created by outreach.py; add contact_email if table already exists
CREATE TABLE IF NOT EXISTS outreach_prospects (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain        TEXT NOT NULL UNIQUE,
    country       TEXT,
    status        TEXT DEFAULT 'pending',   -- pending | approved | sent | rejected
    max_cvss      NUMERIC(4,1),
    contact_email TEXT,
    scanned_at    TIMESTAMPTZ DEFAULT now(),
    approved_at   TIMESTAMPTZ,
    sent_at       TIMESTAMPTZ,
    created_at    TIMESTAMPTZ DEFAULT now()
);

ALTER TABLE outreach_prospects ADD COLUMN IF NOT EXISTS contact_email TEXT;

CREATE INDEX IF NOT EXISTS idx_prospects_status  ON outreach_prospects(status);
CREATE INDEX IF NOT EXISTS idx_prospects_country ON outreach_prospects(country);

ALTER TABLE outreach_prospects DISABLE ROW LEVEL SECURITY;

-- ── API Keys ────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS api_keys (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id          UUID REFERENCES users(id) ON DELETE CASCADE,
    key_hash         TEXT NOT NULL UNIQUE,
    key_prefix       TEXT NOT NULL,
    name             TEXT DEFAULT '',
    calls_this_month INTEGER DEFAULT 0,
    last_used_at     TIMESTAMPTZ,
    created_at       TIMESTAMPTZ DEFAULT now(),
    revoked_at       TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);

ALTER TABLE api_keys DISABLE ROW LEVEL SECURITY;

-- ── Supply Chain Batches ─────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS supply_chain_batches (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      UUID REFERENCES users(id) ON DELETE CASCADE,
    domains      TEXT[] NOT NULL,
    status       TEXT DEFAULT 'running',
    results      JSONB DEFAULT '[]',
    created_at   TIMESTAMPTZ DEFAULT now(),
    completed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_sc_batches_user   ON supply_chain_batches(user_id);
CREATE INDEX IF NOT EXISTS idx_sc_batches_status ON supply_chain_batches(status);

ALTER TABLE supply_chain_batches DISABLE ROW LEVEL SECURITY;

-- ── Competitors ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS competitors (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID REFERENCES users(id) ON DELETE CASCADE,
    domain     TEXT NOT NULL,
    label      TEXT DEFAULT '',
    created_at TIMESTAMPTZ DEFAULT now(),
    UNIQUE(user_id, domain)
);

CREATE INDEX IF NOT EXISTS idx_competitors_user ON competitors(user_id);

ALTER TABLE competitors DISABLE ROW LEVEL SECURITY;

-- ── Competitor Scans ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS competitor_scans (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    competitor_id UUID NOT NULL REFERENCES competitors(id) ON DELETE CASCADE,
    risk_score    INTEGER,
    critical      INTEGER DEFAULT 0,
    warnings      INTEGER DEFAULT 0,
    checks        JSONB DEFAULT '[]',
    scanned_at    TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_comp_scans_competitor ON competitor_scans(competitor_id);
CREATE INDEX IF NOT EXISTS idx_comp_scans_time       ON competitor_scans(scanned_at DESC);

ALTER TABLE competitor_scans DISABLE ROW LEVEL SECURITY;

-- Done!
SELECT 'Migration 001 complete' AS status;
