"""Tests for the /public-scan endpoint — no auth, domain validation, result shape."""
import pytest
from unittest.mock import patch, MagicMock


MOCK_SCAN_RESULT = {
    "domain":     "example.com",
    "risk_score": 35,
    "critical":   1,
    "warnings":   2,
    "scanned_at": "2026-03-22T01:00:00+00:00",
    "checks": [
        {"check": "ssl",     "status": "ok",       "title": "SSL valid",         "detail": "", "score_impact": 0},
        {"check": "headers", "status": "warning",  "title": "Missing HSTS",      "detail": "", "score_impact": 10},
        {"check": "dns",     "status": "ok",       "title": "DNS OK",            "detail": "", "score_impact": 0},
        {"check": "darkweb", "status": "critical", "title": "Breach found",      "detail": "", "score_impact": 25},
        {"check": "cve",     "status": "warning",  "title": "CVE-2024-1234",     "detail": "", "score_impact": 15},
    ],
}


@pytest.fixture()
def scan_mock():
    with patch("main.SCANNER_AVAILABLE", True), \
         patch("cee_scanner.checks.scan_domain", return_value=MOCK_SCAN_RESULT):
        yield


# ── Domain validation ─────────────────────────────────────────────────────────

@pytest.mark.parametrize("bad_domain", [
    "",
    "not-a-domain",
    "http://",
    "../etc/passwd",
    "a" * 300 + ".com",
    "xn--",
    "domain with spaces.com",
    "192.168.1.1",          # raw IP not a domain — backend rejects
])
def test_public_scan_rejects_invalid_domains(client, bad_domain):
    r = client.post("/public-scan", json={"domain": bad_domain})
    assert r.status_code == 400, f"Expected 400 for domain={bad_domain!r}, got {r.status_code}"


@pytest.mark.parametrize("valid_domain", [
    "example.com",
    "sub.example.co.uk",
    "my-company.io",
    "test123.org",
])
def test_public_scan_accepts_valid_domains(client, scan_mock, valid_domain):
    r = client.post("/public-scan", json={"domain": valid_domain})
    assert r.status_code == 200, f"Expected 200 for domain={valid_domain!r}, got {r.status_code}"


# ── URL stripping ─────────────────────────────────────────────────────────────

def test_public_scan_strips_https_prefix(client, scan_mock):
    """Backend should strip https:// before validating."""
    r = client.post("/public-scan", json={"domain": "https://example.com"})
    assert r.status_code == 200


def test_public_scan_strips_path(client, scan_mock):
    """Backend should strip path components."""
    r = client.post("/public-scan", json={"domain": "example.com/some/path"})
    assert r.status_code == 200


# ── Response shape ────────────────────────────────────────────────────────────

def test_public_scan_response_shape(client, scan_mock):
    r = client.post("/public-scan", json={"domain": "example.com"})
    assert r.status_code == 200
    data = r.json()
    assert "domain"     in data
    assert "risk_score" in data
    assert "checks"     in data
    assert "scanned_at" in data
    assert isinstance(data["checks"], list)
    assert isinstance(data["risk_score"], int)


def test_public_scan_locks_non_free_checks(client, scan_mock):
    """Checks outside FREE_CHECKS must be locked for unauthenticated users."""
    r = client.post("/public-scan", json={"domain": "example.com"})
    assert r.status_code == 200
    data = r.json()
    FREE_CHECKS = {"ssl", "headers", "dns", "shodan", "open_ports",
                   "sast", "sca", "dast", "iac", "darkweb"}
    for check in data["checks"]:
        if check["check"] not in FREE_CHECKS:
            assert check["status"] == "locked", (
                f"Check '{check['check']}' should be locked for public scan"
            )


def test_public_scan_not_saved_to_db(client, db_mock, scan_mock):
    """Public scan must NOT write anything to the database."""
    client.post("/public-scan", json={"domain": "example.com"})
    db_mock.table.assert_not_called()


# ── Scanner unavailable ───────────────────────────────────────────────────────

def test_public_scan_503_when_scanner_unavailable(client):
    with patch("main.SCANNER_AVAILABLE", False):
        r = client.post("/public-scan", json={"domain": "example.com"})
        assert r.status_code == 503
