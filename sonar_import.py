"""
sonar_import.py — Rapid7 Project Sonar Bulk Importer
=====================================================

Downloads the latest weekly Rapid7 HTTPS/TLS scan dump and bulk-upserts
hostnames + risk metadata into scan_results without running any active scans.

Run once manually (or schedule weekly after the Render worker is up):
  python3 sonar_import.py --source https --limit 500000 --tlds cz,de,pl,sk,hu,ro,at,ch

Rapid7 Project Sonar — free, no API key needed:
  https://opendata.rapid7.com/sonar.https/   (TLS cert scans)
  https://opendata.rapid7.com/sonar.fdns_v2/ (forward DNS)

What this script does:
  1. Fetches the latest file listing from Rapid7's public S3 index
  2. Streams + decompresses the .json.gz dump line by line (never loads all into RAM)
  3. Extracts hostname, server header, TLS CN/SANs
  4. Filters to requested TLDs (or all if --tlds not set)
  5. Bulk-upserts into scan_results with scan_tier=1, source='sonar'
  6. Skips domains already in scan_results (on_conflict=ignore)

Usage:
  python3 sonar_import.py                          # all TLDs, 100k limit
  python3 sonar_import.py --limit 500000           # 500k domains
  python3 sonar_import.py --tlds cz,sk,pl,hu,ro    # EU only
  python3 sonar_import.py --source fdns            # forward DNS source
  python3 sonar_import.py --dry-run                # parse only, no DB writes
"""

import os
import sys
import json
import gzip
import logging
import argparse
import time
import re
from datetime import datetime, timezone
from io import BytesIO
from typing import Iterator

import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("sonar_import")

# ── Config ────────────────────────────────────────────────────────────────────
SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_KEY", "")

RAPID7_INDEX = {
    "https": "https://opendata.rapid7.com/sonar.https/",
    "fdns":  "https://opendata.rapid7.com/sonar.fdns_v2/",
}

BATCH_SIZE   = 500    # upsert rows per Supabase call
STREAM_CHUNK = 65536  # bytes per streaming read

# ── Supabase client (lightweight — no supabase-py needed) ─────────────────────
def get_db():
    try:
        from supabase import create_client
        return create_client(SUPABASE_URL, SUPABASE_KEY)
    except Exception as e:
        log.error(f"Supabase connection failed: {e}")
        sys.exit(1)

# ── Rapid7 index parser ────────────────────────────────────────────────────────
def get_latest_file_url(source: str) -> str:
    """Scrape the Rapid7 S3 index page to find the most recent .json.gz file."""
    index_url = RAPID7_INDEX[source]
    log.info(f"Fetching Rapid7 index: {index_url}")
    r = requests.get(index_url, timeout=30)
    r.raise_for_status()

    # Find all .json.gz links in the HTML listing
    pattern = r'href="([^"]+\.json\.gz)"'
    matches = re.findall(pattern, r.text)
    if not matches:
        raise ValueError(f"No .json.gz files found in Rapid7 index at {index_url}")

    # Sort by filename (they're date-stamped: 2026-03-01-...) and take latest
    matches.sort(reverse=True)
    latest = matches[0]

    # Build absolute URL if relative
    if latest.startswith("http"):
        return latest
    return index_url.rstrip("/") + "/" + latest.lstrip("/")


# ── Streaming parser ───────────────────────────────────────────────────────────
def stream_sonar_https(url: str, tld_filter: set[str] | None, limit: int) -> Iterator[dict]:
    """
    Stream the Rapid7 HTTPS scan dump line by line.
    Yields dicts with: domain, tld, country, software, server_header
    """
    log.info(f"Streaming: {url}")
    count = 0

    with requests.get(url, stream=True, timeout=120) as resp:
        resp.raise_for_status()

        # Decompress on the fly — never load full file into RAM
        buf = BytesIO()
        gz = None

        for chunk in resp.iter_content(chunk_size=STREAM_CHUNK):
            buf.write(chunk)

        buf.seek(0)
        with gzip.GzipFile(fileobj=buf) as gz_file:
            for raw_line in gz_file:
                if count >= limit:
                    break
                try:
                    rec = json.loads(raw_line.decode("utf-8", errors="replace").strip())
                except (json.JSONDecodeError, UnicodeDecodeError):
                    continue

                # Extract hostname from 'host' or from TLS cert CN
                host = rec.get("host") or rec.get("cn") or ""
                if not host:
                    # Try SANs
                    names = rec.get("names") or []
                    host = names[0] if names else ""
                if not host or "*" in host:
                    continue

                host = host.lower().lstrip(".")
                if not re.match(r'^[a-z0-9][a-z0-9.\-]{1,253}$', host):
                    continue

                # Extract TLD
                parts = host.split(".")
                if len(parts) < 2:
                    continue
                tld = parts[-1]

                if tld_filter and tld not in tld_filter:
                    continue

                # Server header
                server = rec.get("server") or rec.get("data", {}).get("http", {}).get("response", {}).get("headers", {}).get("server", [""])[0] if isinstance(rec.get("data"), dict) else ""

                yield {
                    "domain":  host,
                    "tld":     tld,
                    "server":  (server or "")[:100],
                    "port443": rec.get("port") == 443 or rec.get("ssl") is not None,
                }
                count += 1

    log.info(f"Streamed {count} records from Rapid7")


def stream_sonar_fdns(url: str, tld_filter: set[str] | None, limit: int) -> Iterator[dict]:
    """Stream the Rapid7 forward DNS dump — A records only."""
    log.info(f"Streaming FDNS: {url}")
    count = 0

    with requests.get(url, stream=True, timeout=120) as resp:
        resp.raise_for_status()
        buf = BytesIO()
        for chunk in resp.iter_content(chunk_size=STREAM_CHUNK):
            buf.write(chunk)

    buf.seek(0)
    with gzip.GzipFile(fileobj=buf) as gz_file:
        for raw_line in gz_file:
            if count >= limit:
                break
            try:
                rec = json.loads(raw_line.decode("utf-8", errors="replace").strip())
            except Exception:
                continue

            if rec.get("type") not in ("a", "aaaa"):
                continue

            host = (rec.get("name") or "").lower().rstrip(".")
            if not host or "*" in host:
                continue

            parts = host.split(".")
            if len(parts) < 2:
                continue
            tld = parts[-1]

            if tld_filter and tld not in tld_filter:
                continue

            yield {"domain": host, "tld": tld, "server": "", "port443": False}
            count += 1

    log.info(f"Streamed {count} FDNS records")


# ── TLD → ISO country ─────────────────────────────────────────────────────────
_TLD_COUNTRY = {
    "cz":"CZ","sk":"SK","pl":"PL","hu":"HU","ro":"RO","at":"AT","de":"DE",
    "ch":"CH","fr":"FR","es":"ES","it":"IT","nl":"NL","be":"BE","dk":"DK",
    "se":"SE","no":"NO","fi":"FI","pt":"PT","gr":"GR","hr":"HR","si":"SI",
    "rs":"RS","bg":"BG","lt":"LT","lv":"LV","ee":"EE","ua":"UA","by":"BY",
    "md":"MD","al":"AL","ba":"BA","me":"ME","mk":"MK","xk":"XK","lu":"LU",
    "ie":"IE","is":"IS","mt":"MT","cy":"CY","li":"LI","mc":"MC","ad":"AD",
    "sm":"SM","va":"VA","uk":"GB","gb":"GB",
    "us":"US","ca":"CA","au":"AU","nz":"NZ","jp":"JP","cn":"CN","in":"IN",
    "br":"BR","mx":"MX","ar":"AR","za":"ZA","ru":"RU","tr":"TR","il":"IL",
    "ae":"AE","sg":"SG","hk":"HK","kr":"KR","tw":"TW",
    "com":"US","net":"US","org":"US","io":"IO","co":"CO",
    "eu":"EU","int":"UN","gov":"US","edu":"US","mil":"US",
}


def _make_row(rec: dict) -> dict:
    tld     = rec["tld"]
    country = _TLD_COUNTRY.get(tld, "").upper() or None
    now     = datetime.now(timezone.utc).isoformat()

    # Detect software from server header
    server  = rec.get("server", "")
    software = []
    if server:
        software = [{"product": server, "version": ""}]

    return {
        "domain":         rec["domain"],
        "tld":            tld,
        "country":        country,
        "risk_score":     0,
        "critical":       0,
        "warnings":       0,
        "checks":         [],
        "software":       software,
        "cves":           [],
        "max_cvss":       0,
        "scan_tier":      1,
        "source":         "sonar",
        "priority":       "INFO",
        "last_scanned_at": now,
        "next_scan_at":   now,   # eligible for Tier 1 immediately
        "created_at":     now,
    }


# ── Bulk upsert ───────────────────────────────────────────────────────────────
def upsert_batch(db, rows: list[dict], dry_run: bool) -> int:
    if dry_run:
        log.info(f"  [dry-run] Would upsert {len(rows)} rows")
        return len(rows)
    try:
        db.table("scan_results").upsert(
            rows,
            on_conflict="domain",
            ignore_duplicates=True,   # skip if domain already exists
        ).execute()
        return len(rows)
    except Exception as e:
        log.warning(f"  Batch upsert error (skipping): {e}")
        return 0


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Import Rapid7 Project Sonar data into SwarmHawk scan_results")
    parser.add_argument("--source",  choices=["https", "fdns"], default="https", help="Sonar dataset (https=TLS scans, fdns=DNS records)")
    parser.add_argument("--limit",   type=int, default=100_000, help="Max domains to import (default: 100000)")
    parser.add_argument("--tlds",    default="", help="Comma-separated TLD filter, e.g. cz,de,pl (empty=all)")
    parser.add_argument("--dry-run", action="store_true", help="Parse only — do not write to DB")
    parser.add_argument("--url",     default="", help="Override file URL (skip index lookup)")
    args = parser.parse_args()

    if not args.dry_run and (not SUPABASE_URL or not SUPABASE_KEY):
        log.error("Set SUPABASE_URL and SUPABASE_SERVICE_KEY env vars (or use --dry-run)")
        sys.exit(1)

    tld_filter = set(args.tlds.lower().split(",")) - {""} if args.tlds else None
    if tld_filter:
        log.info(f"TLD filter: {sorted(tld_filter)}")
    else:
        log.info("No TLD filter — importing all TLDs")

    # Resolve file URL
    file_url = args.url or get_latest_file_url(args.source)
    log.info(f"Source file: {file_url}")

    # Stream + parse
    stream_fn = stream_sonar_https if args.source == "https" else stream_sonar_fdns

    db = None if args.dry_run else get_db()

    batch   = []
    total   = 0
    skipped = 0
    t_start = time.time()

    for rec in stream_fn(file_url, tld_filter, args.limit):
        row = _make_row(rec)
        batch.append(row)

        if len(batch) >= BATCH_SIZE:
            written = upsert_batch(db, batch, args.dry_run)
            total  += written
            skipped += len(batch) - written
            batch   = []
            elapsed = time.time() - t_start
            rate    = total / elapsed if elapsed > 0 else 0
            log.info(f"  Progress: {total:,} imported | {rate:.0f}/sec | elapsed {elapsed:.0f}s")

    # Final batch
    if batch:
        written = upsert_batch(db, batch, args.dry_run)
        total  += written

    elapsed = time.time() - t_start
    log.info(f"Done. Imported {total:,} domains in {elapsed:.1f}s ({total/elapsed:.0f}/sec)")
    if skipped:
        log.info(f"Skipped {skipped:,} (already in scan_results)")


if __name__ == "__main__":
    main()
