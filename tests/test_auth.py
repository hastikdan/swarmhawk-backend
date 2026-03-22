"""Tests for authentication and authorization logic."""
import pytest
from fastapi import HTTPException
from unittest.mock import patch, MagicMock


# ── get_user_from_header ──────────────────────────────────────────────────────

def test_get_user_missing_header(db_mock):
    with patch("main.get_db", return_value=db_mock):
        import main
        with pytest.raises(HTTPException) as exc:
            main.get_user_from_header(None)
        assert exc.value.status_code == 401


def test_get_user_no_bearer_prefix(db_mock):
    with patch("main.get_db", return_value=db_mock):
        import main
        with pytest.raises(HTTPException) as exc:
            main.get_user_from_header("notabearer token123")
        assert exc.value.status_code == 401


def test_get_user_invalid_token(db_mock):
    """Token not found in sessions table → 401."""
    chain = MagicMock()
    chain.execute.return_value = MagicMock(data=[])  # empty = not found
    chain.select.return_value = chain
    chain.eq.return_value = chain
    db_mock.table.return_value = chain

    with patch("main.get_db", return_value=db_mock):
        import main
        with pytest.raises(HTTPException) as exc:
            main.get_user_from_header("Bearer invalid-token")
        assert exc.value.status_code == 401


def test_get_user_valid_token(db_mock):
    """Valid token in sessions table → returns user dict with sub."""
    chain = MagicMock()
    chain.execute.return_value = MagicMock(data=[{"user_id": "abc-123"}])
    chain.select.return_value = chain
    chain.eq.return_value = chain
    db_mock.table.return_value = chain

    with patch("main.get_db", return_value=db_mock):
        import main
        user = main.get_user_from_header("Bearer valid-token")
        assert user["sub"] == "abc-123"


# ── is_admin ──────────────────────────────────────────────────────────────────

def test_is_admin_true(db_mock):
    chain = MagicMock()
    chain.execute.return_value = MagicMock(data=[{"email": "admin@swarmhawk.com"}])
    chain.select.return_value = chain
    chain.eq.return_value = chain
    db_mock.table.return_value = chain

    with patch("main.get_db", return_value=db_mock), \
         patch("main.ADMIN_EMAIL", "admin@swarmhawk.com"):
        import main
        assert main.is_admin("admin-uuid") is True


def test_is_admin_false_wrong_email(db_mock):
    chain = MagicMock()
    chain.execute.return_value = MagicMock(data=[{"email": "other@example.com"}])
    chain.select.return_value = chain
    chain.eq.return_value = chain
    db_mock.table.return_value = chain

    with patch("main.get_db", return_value=db_mock), \
         patch("main.ADMIN_EMAIL", "admin@swarmhawk.com"):
        import main
        assert main.is_admin("other-uuid") is False


def test_is_admin_false_no_admin_email(db_mock):
    with patch("main.get_db", return_value=db_mock), \
         patch("main.ADMIN_EMAIL", ""):
        import main
        assert main.is_admin("any-uuid") is False


# ── Protected endpoints return 401 without token ─────────────────────────────

@pytest.mark.parametrize("method,path,body", [
    ("GET",   "/domains",               None),
    ("POST",  "/domains",               {"domain": "example.com", "country": "CZ"}),
    ("GET",   "/admin/stats",           None),
    ("GET",   "/admin/portkey/usage",   None),
    ("POST",  "/pipeline/run-discovery",None),
    ("POST",  "/pipeline/run-tier1",    None),
    ("POST",  "/pipeline/run-tier2",         None),
    ("POST",  "/pipeline/run-bulk-discovery",None),
])
def test_protected_endpoints_require_auth(client, method, path, body):
    kwargs = {"json": body} if body else {}
    r = client.request(method, path, **kwargs)
    assert r.status_code in (401, 403), (
        f"{method} {path} should require auth, got {r.status_code}"
    )


# ── Admin-only endpoints return 403 for regular users ────────────────────────

@pytest.mark.parametrize("method,path", [
    ("GET",  "/admin/stats"),
    ("POST", "/pipeline/run-discovery"),
    ("POST", "/pipeline/run-tier1"),
    ("POST", "/pipeline/run-tier2"),
    ("POST", "/pipeline/run-bulk-discovery"),
])
def test_admin_endpoints_reject_regular_users(client, user_token, method, path):
    r = client.request(method, path, headers={"Authorization": user_token})
    assert r.status_code == 403, (
        f"{method} {path} should be admin-only, got {r.status_code}"
    )
