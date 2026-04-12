-- Migration 016: SQL function for efficient pipeline daily stats aggregation.
--
-- Groups scan_results by DATE(last_scanned_at) server-side so Render doesn't
-- need to pull millions of timestamp rows to count them in Python.
--
-- Called via: db.rpc("pipeline_daily_stats", {"days_back": 14})
-- Returns rows: { scan_date, pipeline_scanned, outreach_found, geo_enriched }

CREATE OR REPLACE FUNCTION pipeline_daily_stats(days_back INT DEFAULT 14)
RETURNS TABLE (
    scan_date        DATE,
    pipeline_scanned BIGINT,   -- domains processed by Tier 1 that day
    outreach_found   BIGINT,   -- domains that became outreach prospects that day
    geo_enriched     BIGINT    -- domains geo-tagged (ip_asn populated) that day
) AS $$
    SELECT
        DATE(last_scanned_at)                                              AS scan_date,
        COUNT(*)                                                           AS pipeline_scanned,
        COUNT(*) FILTER (WHERE outreach_status IS NOT NULL)                AS outreach_found,
        COUNT(*) FILTER (WHERE ip_asn IS NOT NULL AND ip_asn <> '')        AS geo_enriched
    FROM scan_results
    WHERE last_scanned_at >= CURRENT_DATE - days_back
      AND last_scanned_at IS NOT NULL
    GROUP BY DATE(last_scanned_at)
    ORDER BY scan_date;
$$ LANGUAGE sql SECURITY DEFINER;

-- Grant execution to service role (used by backend admin queries)
GRANT EXECUTE ON FUNCTION pipeline_daily_stats(INT) TO service_role;
