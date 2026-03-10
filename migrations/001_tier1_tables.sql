-- SwarmHawk TIER 1 Schema Migration
-- Run this in the Supabase SQL editor

-- ── API Keys ────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS api_keys (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         TEXT NOT NULL,
    key_hash        TEXT NOT NULL UNIQUE,   -- SHA-256 hash of the actual key
    key_prefix      TEXT NOT NULL,          -- First 8 chars for display (e.g. "sh_live_")
    name            TEXT DEFAULT '',
    calls_this_month INTEGER DEFAULT 0,
    last_used_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ DEFAULT now(),
    revoked_at      TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);

-- RLS: users can only see their own keys
ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;
CREATE POLICY "api_keys_owner" ON api_keys
    USING (auth.uid()::text = user_id);

-- ── Supply Chain Batches ─────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS supply_chain_batches (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     TEXT NOT NULL,
    domains     TEXT[] NOT NULL,           -- list of vendor domains submitted
    status      TEXT DEFAULT 'running',    -- running | done | failed
    results     JSONB DEFAULT '[]',
    created_at  TIMESTAMPTZ DEFAULT now(),
    completed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_sc_batches_user ON supply_chain_batches(user_id);
CREATE INDEX IF NOT EXISTS idx_sc_batches_status ON supply_chain_batches(status);

ALTER TABLE supply_chain_batches ENABLE ROW LEVEL SECURITY;
CREATE POLICY "sc_batches_owner" ON supply_chain_batches
    USING (auth.uid()::text = user_id);

-- ── Competitors ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS competitors (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     TEXT NOT NULL,
    domain      TEXT NOT NULL,
    label       TEXT DEFAULT '',
    created_at  TIMESTAMPTZ DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_competitors_unique ON competitors(user_id, domain);
CREATE INDEX IF NOT EXISTS idx_competitors_user ON competitors(user_id);

ALTER TABLE competitors ENABLE ROW LEVEL SECURITY;
CREATE POLICY "competitors_owner" ON competitors
    USING (auth.uid()::text = user_id);

-- ── Competitor Scans ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS competitor_scans (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    competitor_id   UUID NOT NULL REFERENCES competitors(id) ON DELETE CASCADE,
    risk_score      INTEGER,
    critical        INTEGER DEFAULT 0,
    warnings        INTEGER DEFAULT 0,
    checks          JSONB DEFAULT '[]',
    scanned_at      TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_comp_scans_competitor ON competitor_scans(competitor_id);
CREATE INDEX IF NOT EXISTS idx_comp_scans_time ON competitor_scans(scanned_at DESC);

-- No RLS needed — access controlled via competitor ownership check in API

-- ── Outreach contact_email column (if missing) ───────────────────────────────
ALTER TABLE outreach_prospects
    ADD COLUMN IF NOT EXISTS contact_email TEXT;

-- Done!
SELECT 'Migration 001 complete' AS status;
