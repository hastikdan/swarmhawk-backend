-- Migration 008: Integration configs table
-- Stores per-user, per-service integration settings for XDR/SIEM push connectors.
-- Run manually in Supabase SQL editor.

CREATE TABLE IF NOT EXISTS integration_configs (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       UUID REFERENCES users(id) ON DELETE CASCADE,
    service       TEXT NOT NULL,   -- splunk | sentinel | crowdstrike | gravityzone | cortex | jira | servicenow | webhook | stix
    config        JSONB NOT NULL,  -- platform-specific credentials/URLs (stored encrypted at app layer)
    enabled       BOOLEAN NOT NULL DEFAULT true,
    last_fired_at TIMESTAMPTZ,
    error_count   INTEGER NOT NULL DEFAULT 0,
    last_error    TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(user_id, service)
);

CREATE INDEX idx_integration_configs_user    ON integration_configs(user_id);
CREATE INDEX idx_integration_configs_service ON integration_configs(service);
