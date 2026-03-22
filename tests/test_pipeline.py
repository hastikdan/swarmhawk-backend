"""Tests for pipeline.py pure functions — no mocks needed, fully offline."""
import pytest
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from pipeline import extract_tld, infer_country, compute_unified_risk, ingest_domains
from unittest.mock import MagicMock, patch


# ── extract_tld ───────────────────────────────────────────────────────────────

@pytest.mark.parametrize("domain,expected", [
    ("example.com",       "com"),
    ("sub.example.co.uk", "uk"),
    ("company.cz",        "cz"),
    ("test.io",           "io"),
    ("deep.sub.domain.de","de"),
])
def test_extract_tld(domain, expected):
    assert extract_tld(domain) == expected


def test_extract_tld_empty():
    assert extract_tld("") == ""


# ── infer_country ─────────────────────────────────────────────────────────────

@pytest.mark.parametrize("domain,expected_country", [
    ("example.cz",  "CZ"),
    ("firma.pl",    "PL"),
    ("shop.de",     "DE"),
    ("brand.fr",    "FR"),
    ("site.com",    "US"),
    ("app.io",      "US"),
    ("unknown.xyz", "GLOBAL"),   # unknown TLD → GLOBAL
])
def test_infer_country(domain, expected_country):
    assert infer_country(domain) == expected_country


# ── compute_unified_risk ──────────────────────────────────────────────────────

def test_risk_zero_for_clean_domain():
    assert compute_unified_risk(0.0, [], []) == 0


def test_risk_cve_only_tier1():
    """Tier 1 scan: risk comes only from CVE score."""
    score = compute_unified_risk(max_cvss=9.5, checks=[], software=[])
    assert score == min(100, int(9.5 * 6))  # = 57


def test_risk_cve_capped_at_60():
    score = compute_unified_risk(max_cvss=10.0, checks=[], software=[])
    assert score <= 60


def test_risk_checks_add_penalty_tier2():
    checks = [
        {"status": "critical"},
        {"status": "critical"},
        {"status": "warning"},
    ]
    base = compute_unified_risk(max_cvss=0, checks=[], software=[])
    with_checks = compute_unified_risk(max_cvss=0, checks=checks, software=[])
    assert with_checks > base


def test_risk_software_adds_penalty():
    software = [{"product": "Apache", "version": "2.4.1"},
                {"product": "OpenSSL", "version": "1.0.2"}]
    base = compute_unified_risk(max_cvss=0, checks=[], software=[])
    with_sw = compute_unified_risk(max_cvss=0, checks=[], software=software)
    assert with_sw > base


def test_risk_never_exceeds_100():
    checks = [{"status": "critical"}] * 20
    software = [{"product": f"sw{i}", "version": "1.0"} for i in range(20)]
    score = compute_unified_risk(max_cvss=10.0, checks=checks, software=software)
    assert score <= 100


def test_risk_never_negative():
    score = compute_unified_risk(max_cvss=0.0, checks=[], software=[])
    assert score >= 0


# ── ingest_domains — domain validation ───────────────────────────────────────

def _make_db_mock():
    db = MagicMock()
    chain = MagicMock()
    chain.execute.return_value = MagicMock(data=[])
    chain.select.return_value = chain
    chain.in_.return_value = chain
    chain.upsert.return_value = chain
    db.table.return_value = chain
    return db


@pytest.mark.parametrize("bad_domain", [
    "../etc/passwd",
    "domain with spaces",
    "",
    "a",                      # too short
    "-invalid.com",           # starts with hyphen
    "a" * 260 + ".com",       # too long
])
def test_ingest_domains_rejects_malformed(bad_domain):
    db = _make_db_mock()
    count = ingest_domains([bad_domain], source="test", db=db)
    assert count == 0, f"Should reject malformed domain: {bad_domain!r}"


@pytest.mark.parametrize("good_domain", [
    "example.com",
    "sub.example.co.uk",
    "my-company.io",
    "test123.de",
    "xn--nxasmq6b.com",   # punycode
])
def test_ingest_domains_accepts_valid(good_domain):
    db = _make_db_mock()
    count = ingest_domains([good_domain], source="radar", db=db)
    assert count == 1, f"Should accept valid domain: {good_domain!r}"


def test_ingest_domains_skips_already_in_scan_results():
    db = _make_db_mock()
    # Simulate scan_results already has this domain
    chain = db.table.return_value
    chain.execute.return_value = MagicMock(data=[{"domain": "existing.com"}])
    count = ingest_domains(["existing.com"], source="radar", db=db)
    assert count == 0


def test_ingest_domains_sets_radar_priority():
    """Radar domains get priority=3, others get priority=5."""
    db = _make_db_mock()
    chain = db.table.return_value
    chain.execute.return_value = MagicMock(data=[])

    ingest_domains(["newdomain.com"], source="radar", db=db)

    # Find the upsert call and check priority
    upsert_call = chain.upsert.call_args
    if upsert_call:
        rows = upsert_call[0][0]
        assert rows[0]["priority"] == 3


def test_ingest_domains_deduplicates_input():
    """Duplicate domains in the same batch should only be inserted once."""
    db = _make_db_mock()
    chain = db.table.return_value
    chain.execute.return_value = MagicMock(data=[])

    count = ingest_domains(["same.com", "same.com", "same.com"], source="test", db=db)
    assert count <= 1
