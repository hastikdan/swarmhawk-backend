# SwarmHawk — Global Domain Security Pipeline

## Vision
World's largest domain security database. Every domain on the internet, scanned weekly
with 22 checks, producing a proprietary vulnerability timeline graph. Self-feeding
outreach machine: new vulnerable domains discovered daily → auto-qualified leads → sales.

---

## Phase 1 — Foundation (IN PROGRESS)

- [x] `migrations/004_scan_results.sql` — unified `scan_results` + `domain_queue` tables
- [x] `pipeline.py` — core pipeline module (discovery, Tier 1, Tier 2, upsert)
- [x] `outreach.py` — dual-write: scan results go to BOTH `outreach_prospects` AND `scan_results`
- [x] `main.py` — map endpoints read from `scan_results`; daily discovery + weekly enrichment crons
- [ ] Run migration in Supabase (user must run 004_scan_results.sql)
- [ ] Set CLOUDFLARE_API_TOKEN in Render env vars (if not already set)
- [ ] Deploy backend

## Phase 2 — Full Outreach Migration

- [ ] Migrate outreach tab endpoints to read from `scan_results` instead of `outreach_prospects`
- [ ] Add Certificate Transparency log streaming (crt.sh -> new domains)
- [ ] Add Cisco Umbrella 1M weekly download (global top-1M domains)
- [ ] Remove dual-write once migration verified stable

## Phase 3 — Scale

- [ ] CZDS zone file ingestion (complete TLD coverage -- register at czds.icann.org)
- [ ] Priority queue: rank-weighted scan scheduling
- [ ] Vulnerability delta alerting: email when risk_score increases significantly
- [ ] Paid API: sell /scan_results query access
- [ ] Dashboard analytics: global vulnerability heat map, trend charts

---

## Architecture

Discovery (daily 01:00)      Tier 1 (daily 02:00)    Tier 2 (weekly Sun 03:00)
Cloudflare Radar top-100  -> domain_queue         ->  scan_results (full 22 checks)
  per country, ALL          (new domains only)        oldest last_scanned_at first
CT logs (crt.sh)          -> Tier 1 scan          ->  update in-place
Umbrella 1M (weekly)      -> 2 checks, 50 workers ->  5000 domains/run
                          -> upsert to:
                             - scan_results
                             - outreach_prospects (dual-write, Phase 1)

## Unified Risk Score (0-100)
  CVE component:      min(60, max_cvss * 6)
  Check penalties:    min(20, critical*5 + warnings*2)  [Tier 2 only]
  Software component: min(20, len(vulnerable_sw)*5)
