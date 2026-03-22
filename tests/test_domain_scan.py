"""Tests for authenticated domain scan endpoints (/api/v1/scan, /api/v2/scan)."""
import pytest
from unittest.mock import patch, MagicMock

MOCK_SCAN = {
    "domain": "target.cz",
    "risk_score": 45,
    "critical": 1,
    "warnings": 3,
    "scanned_at": "2026-03-22T02:00:00+00:00",
    "checks": [
        {"check": "ssl",     "status": "ok",      "title": "SSL OK",       "detail": "", "score_impact": 0},
        {"check": "headers", "status": "warning", "title": "Missing HSTS", "detail": "", "score_impact": 10},
    ],
}


@pytest.fixture()
def api_scan_mock():
    with patch("main.SCANNER_AVAILABLE", True), \
         patch("cee_scanner.checks.scan_domain", return_value=MOCK_SCAN):
        yield


# ── /api/v1/scan ──────────────────────────────────────────────────────────────

def test_v1_scan_requires_auth(client):
    r = client.post("/api/v1/scan", json={"domain": "example.com"})
    assert r.status_code in (401, 403)


def test_v1_scan_bad_domain_rejected(client, db_mock, user_token):
    """Domain validation runs after auth — set up a working auth chain."""
    default_chain = MagicMock()
    default_chain.execute.return_value = MagicMock(data=[])
    for m in ("select","eq","is_","order","limit","insert","update","upsert","delete","in_"):
        getattr(default_chain, m).return_value = default_chain

    sessions_chain = MagicMock()
    sessions_chain.execute.return_value = MagicMock(data=[{"user_id": "user-uuid"}])
    sessions_chain.select.return_value = sessions_chain
    sessions_chain.eq.return_value = sessions_chain

    db_mock.table.side_effect = lambda name: sessions_chain if name == "sessions" else default_chain

    r = client.post("/api/v1/scan",
                    json={"domain": "../etc/passwd"},
                    headers={"Authorization": user_token})
    assert r.status_code == 400


def test_v1_scan_returns_result(client, user_token, api_scan_mock, db_mock):
    # Mock api_keys table returning no key (no quota check)
    chain = MagicMock()
    chain.execute.return_value = MagicMock(data=[])
    chain.select.return_value = chain
    chain.eq.return_value = chain
    chain.is_.return_value = chain

    def table_router(name):
        if name in ("api_keys",): return chain
        # sessions: user_token resolves to user-uuid
        if name == "sessions":
            s = MagicMock()
            s.execute.return_value = MagicMock(data=[{"user_id": "user-uuid"}])
            s.select.return_value = s
            s.eq.return_value = s
            return s
        return chain

    db_mock.table.side_effect = table_router

    r = client.post("/api/v1/scan",
                    json={"domain": "target.cz"},
                    headers={"Authorization": user_token})
    assert r.status_code == 200
    data = r.json()
    assert "risk_score" in data
    assert "checks" in data


# ── /api/v2/scan ──────────────────────────────────────────────────────────────

def test_v2_scan_requires_auth(client):
    r = client.post("/api/v2/scan", json={"domain": "example.com"})
    assert r.status_code in (401, 403)


def test_v2_scan_bad_domain_rejected(client, db_mock, user_token):
    default_chain = MagicMock()
    default_chain.execute.return_value = MagicMock(data=[])
    for m in ("select","eq","is_","order","limit","insert","update","upsert","delete","in_"):
        getattr(default_chain, m).return_value = default_chain

    sessions_chain = MagicMock()
    sessions_chain.execute.return_value = MagicMock(data=[{"user_id": "user-uuid"}])
    sessions_chain.select.return_value = sessions_chain
    sessions_chain.eq.return_value = sessions_chain

    db_mock.table.side_effect = lambda name: sessions_chain if name == "sessions" else default_chain

    r = client.post("/api/v2/scan",
                    json={"domain": "not_a_domain"},
                    headers={"Authorization": user_token})
    assert r.status_code == 400


# ── API key rate limiting ─────────────────────────────────────────────────────

def test_v1_scan_api_key_over_limit_rejected(client, db_mock, api_scan_mock):
    """API key that has hit its monthly limit should get 429."""
    api_key_chain = MagicMock()
    api_key_chain.execute.return_value = MagicMock(data=[{
        "id":               "key-uuid",
        "calls_this_month": 1000,
        "limit_per_month":  100,
        "revoked_at":       None,
    }])
    api_key_chain.select.return_value = api_key_chain
    api_key_chain.eq.return_value = api_key_chain
    api_key_chain.is_.return_value = api_key_chain

    db_mock.table.side_effect = lambda name: api_key_chain

    r = client.post("/api/v1/scan",
                    json={"domain": "example.com"},
                    headers={"X-API-Key": "swh_test_key"})
    assert r.status_code == 429
