"""
pipeline_worker.py — SwarmHawk Standalone Pipeline Worker
==========================================================

Run this as a separate Render Background Worker service (not a web server).
It owns all scheduled scanning so the web dyno stays lean and never OOMs.

Env vars (set only on the worker service in Render):
  PIPELINE_WORKERS      = 20       (default; 50 causes OOM on free tier)
  PIPELINE_TIER1_BATCH  = 3500     (domains per 4-hour Tier 1 run)
  PIPELINE_TIER2_BATCH  = 500      (full 22-check enrichment per weekly run)
  PIPELINE_RADAR_LIMIT  = 200
  PIPELINE_BULK_LIMIT   = 250000
  SUPABASE_URL          (required)
  SUPABASE_SERVICE_KEY  (required)

Usage:
  python3 pipeline_worker.py
"""

import os
import sys
import signal
import logging
import time
from datetime import datetime

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("worker")

# ── Verify required env vars before importing heavy deps ─────────────────────
SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_KEY", "")

if not SUPABASE_URL or not SUPABASE_KEY:
    log.error("SUPABASE_URL and SUPABASE_SERVICE_KEY must be set. Exiting.")
    sys.exit(1)

log.info("SwarmHawk Pipeline Worker starting up…")
log.info(f"  PIPELINE_WORKERS     = {os.getenv('PIPELINE_WORKERS', '20')}")
log.info(f"  PIPELINE_TIER1_BATCH = {os.getenv('PIPELINE_TIER1_BATCH', '3500')}")
log.info(f"  PIPELINE_TIER2_BATCH = {os.getenv('PIPELINE_TIER2_BATCH', '500')}")

# ── Import pipeline functions ─────────────────────────────────────────────────
try:
    from pipeline import (
        run_discovery_job,
        run_pipeline_daily,
        run_enrichment_weekly,
        run_bulk_discovery_job,
    )
except ImportError as e:
    log.error(f"Failed to import pipeline.py: {e}")
    sys.exit(1)

try:
    import sonar_import as _sonar
    def run_sonar_monthly():
        log.info("[sonar] Starting monthly Rapid7 HTTPS import (limit=500k)…")
        try:
            file_url = _sonar.get_latest_file_url("https")
            db = _sonar.get_db()
            batch, total = [], 0
            for rec in _sonar.stream_sonar_https(file_url, None, 500_000):
                batch.append(_sonar._make_row(rec))
                if len(batch) >= _sonar.BATCH_SIZE:
                    total += _sonar.upsert_batch(db, batch, dry_run=False)
                    batch = []
            if batch:
                total += _sonar.upsert_batch(db, batch, dry_run=False)
            log.info(f"[sonar] Done — {total:,} domains upserted")
        except Exception as exc:
            log.error(f"[sonar] Import failed: {exc}")
    _SONAR_AVAILABLE = True
except ImportError:
    log.warning("sonar_import.py not found — monthly Sonar job disabled")
    _SONAR_AVAILABLE = False

# ── Scheduler ─────────────────────────────────────────────────────────────────
try:
    from apscheduler.schedulers.blocking import BlockingScheduler
    from apscheduler.triggers.cron import CronTrigger
except ImportError:
    log.error("apscheduler not installed — run: pip install apscheduler")
    sys.exit(1)

scheduler = BlockingScheduler(timezone="Europe/Prague")

# Daily 01:00 — Radar + CT logs + Majestic discovery
scheduler.add_job(
    run_discovery_job,
    CronTrigger(hour=1, minute=0),
    id="discovery",
    name="Daily domain discovery",
    max_instances=1,
    misfire_grace_time=3600,
)

# Every 4 hours — Tier 1 batch scan (software + CVE)
scheduler.add_job(
    run_pipeline_daily,
    CronTrigger(hour="0,4,8,12,16,20", minute=30),
    id="tier1",
    name="Tier 1 batch scan",
    max_instances=1,
    misfire_grace_time=1800,
)

# Weekly Sunday 03:00 — Tier 2 full 22-check enrichment
scheduler.add_job(
    run_enrichment_weekly,
    CronTrigger(day_of_week="sun", hour=3, minute=0),
    id="tier2",
    name="Tier 2 weekly enrichment",
    max_instances=1,
    misfire_grace_time=7200,
)

# Weekly Saturday 00:00 — Bulk discovery (Tranco + Umbrella)
scheduler.add_job(
    run_bulk_discovery_job,
    CronTrigger(day_of_week="sat", hour=0, minute=0),
    id="bulk_discovery",
    name="Bulk domain discovery",
    max_instances=1,
    misfire_grace_time=7200,
)

# Monthly 1st of month 02:00 — Rapid7 Sonar bulk import
if _SONAR_AVAILABLE:
    scheduler.add_job(
        run_sonar_monthly,
        CronTrigger(day=1, hour=2, minute=0),
        id="sonar_import",
        name="Monthly Rapid7 Sonar import",
        max_instances=1,
        misfire_grace_time=7200,
    )

# ── Heartbeat ─────────────────────────────────────────────────────────────────
def _heartbeat():
    jobs = scheduler.get_jobs()
    for job in jobs:
        next_run = job.next_run_time
        log.info(f"  [{job.id}] next run: {next_run}")

scheduler.add_job(
    _heartbeat,
    CronTrigger(minute=0),   # log next-run times every hour
    id="heartbeat",
    name="Heartbeat",
)

# ── Warm start — run Tier 1 immediately on startup to drain the queue ─────────
def _warm_start():
    log.info("[warm_start] Running initial Tier 1 batch on startup…")
    try:
        run_pipeline_daily()
    except Exception as e:
        log.error(f"[warm_start] Tier 1 failed: {e}")

scheduler.add_job(
    _warm_start,
    "date",   # fire once immediately at startup
    id="warm_start",
    name="Warm start Tier 1",
)

# ── Graceful shutdown ─────────────────────────────────────────────────────────
def _shutdown(signum, frame):
    log.info(f"Received signal {signum} — shutting down scheduler…")
    scheduler.shutdown(wait=False)
    sys.exit(0)

signal.signal(signal.SIGTERM, _shutdown)
signal.signal(signal.SIGINT,  _shutdown)

# ── Start ──────────────────────────────────────────────────────────────────────
log.info("Scheduler configured. Jobs:")
for job in scheduler.get_jobs():
    log.info(f"  [{job.id}] {job.name}")

log.info("Starting blocking scheduler — worker is live.")
try:
    scheduler.start()
except (KeyboardInterrupt, SystemExit):
    log.info("Worker stopped.")
