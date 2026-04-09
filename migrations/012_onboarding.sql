-- Migration 012: User onboarding role and completion flag
-- Run manually in Supabase SQL editor

ALTER TABLE users ADD COLUMN IF NOT EXISTS onboarding_role TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS onboarding_completed BOOLEAN DEFAULT FALSE;
