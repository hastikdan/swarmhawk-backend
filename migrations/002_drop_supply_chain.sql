-- SwarmHawk Migration 002
-- Remove supply_chain_batches table (feature removed from product)
-- Paste into Supabase → SQL Editor → Run

DROP TABLE IF EXISTS supply_chain_batches;

SELECT 'Migration 002 complete — supply_chain_batches removed' AS status;
