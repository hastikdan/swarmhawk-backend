"""
cee_scanner.scanner
===================
Main scanning engine.
Runs all checks in parallel (thread pool) for speed.
Saves results to JSON for the dashboard.
"""

import json
import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

from .checks import scan_domain
from .targets import TARGETS

logger = logging.getLogger("cee_scanner.scanner")


class Scanner:
    def __init__(self, output_dir: str = "./data", max_workers: int = 10):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.max_workers = max_workers
        self._lock = threading.Lock()
        self._progress = 0
        self._total = 0

    def run_all(self, countries: list = None) -> dict:
        """
        Scan all targets for specified countries.
        Returns full results dict.
        """
        targets = {
            k: v for k, v in TARGETS.items()
            if countries is None or k in countries
        }

        all_domains = [
            (country, domain)
            for country, domains in targets.items()
            for domain in domains
        ]

        self._total = len(all_domains)
        self._progress = 0

        print(f"\n  Scanning {self._total} domains across {len(targets)} countries...")
        print(f"  Workers: {self.max_workers} parallel\n")

        results = {country: [] for country in targets}

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_domain = {
                executor.submit(scan_domain, domain): (country, domain)
                for country, domain in all_domains
            }

            for future in as_completed(future_to_domain):
                country, domain = future_to_domain[future]
                try:
                    result = future.result()
                    with self._lock:
                        results[country].append(result)
                        self._progress += 1
                        self._print_progress(domain, result)
                except Exception as e:
                    logger.error(f"Scan failed for {domain}: {e}")
                    with self._lock:
                        self._progress += 1

        # Sort each country by risk score (highest first)
        for country in results:
            results[country].sort(key=lambda x: x["risk_score"], reverse=True)

        # Build full report
        report = self._build_report(results, targets)

        # Save to file
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        output_path = self.output_dir / f"scan_{ts}.json"
        latest_path = self.output_dir / "latest.json"

        output_path.write_text(json.dumps(report, indent=2))
        latest_path.write_text(json.dumps(report, indent=2))

        print(f"\n  Results saved → {output_path}")
        print(f"  Latest → {latest_path}\n")

        return report

    def _print_progress(self, domain: str, result: dict):
        pct = int(self._progress / self._total * 100)
        bar = "█" * (pct // 5) + "░" * (20 - pct // 5)
        status_icon = {
            0: "✓",
        }.get(result["critical"], "!")
        risk = result["risk_score"]
        color = "\033[91m" if risk >= 60 else "\033[93m" if risk >= 30 else "\033[92m"
        reset = "\033[0m"
        print(
            f"  [{bar}] {pct:3d}%  "
            f"{color}{status_icon}{reset}  "
            f"{domain:<35}  risk={risk:3d}  "
            f"crit={result['critical']}  warn={result['warnings']}"
        )

    def _build_report(self, results: dict, targets: dict) -> dict:
        """Build the full structured report."""
        now = datetime.now(timezone.utc).isoformat()

        country_summaries = {}
        for country, domain_results in results.items():
            if not domain_results:
                continue
            avg_risk = sum(r["risk_score"] for r in domain_results) / len(domain_results)
            total_critical = sum(r["critical"] for r in domain_results)
            total_warnings = sum(r["warnings"] for r in domain_results)
            highest_risk = domain_results[0] if domain_results else None

            country_summaries[country] = {
                "domain_count": len(domain_results),
                "avg_risk_score": round(avg_risk, 1),
                "total_critical": total_critical,
                "total_warnings": total_warnings,
                "highest_risk_domain": highest_risk["domain"] if highest_risk else None,
                "highest_risk_score": highest_risk["risk_score"] if highest_risk else 0,
                "domains": domain_results,
            }

        # Global stats
        all_results = [r for dr in results.values() for r in dr]
        global_avg = (
            sum(r["risk_score"] for r in all_results) / len(all_results)
            if all_results else 0
        )

        return {
            "generated_at": now,
            "scan_type": "passive_osint",
            "countries": list(targets.keys()),
            "total_domains": len(all_results),
            "global_avg_risk": round(global_avg, 1),
            "country_summaries": country_summaries,
        }
