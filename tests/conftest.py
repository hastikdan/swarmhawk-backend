"""
Shared fixtures for SwarmHawk backend tests.

All Supabase, Stripe, and external API calls are mocked —
tests run fully offline with no credentials needed.
"""
import os
import pytest
from unittest.mock import MagicMock, patch

# ── Set dummy env vars before any app import ─────────────────────────────────
os.environ.setdefault("SUPABASE_URL",         "https://fake.supabase.co")
os.environ.setdefault("SUPABASE_KEY",         "fake-anon-key")
os.environ.setdefault("SUPABASE_SERVICE_KEY", "fake-service-key")
os.environ.setdefault("ADMIN_EMAIL",          "admin@swarmhawk.com")
os.environ.setdefault("SECRET_SALT",          "test-salt")
os.environ.setdefault("STRIPE_SECRET_KEY",    "sk_test_fake")
os.environ.setdefault("STRIPE_WEBHOOK_SECRET","whsec_fake")
os.environ.setdefault("CLOUDFLARE_API_TOKEN", "fake-cf-token")
os.environ.setdefault("PORTKEY_API_KEY",      "fake-portkey-key")
os.environ.setdefault("PORTKEY_WORKSPACE_SLUG","fake-workspace")


def _make_supabase_mock():
    """Return a Supabase client mock that chains .table().select()...execute() cleanly."""
    mock = MagicMock()
    chain = MagicMock()
    chain.execute.return_value = MagicMock(data=[], count=0)
    # Every table/select/eq/... returns the same chainable mock
    mock.table.return_value = chain
    chain.select.return_value = chain
    chain.insert.return_value = chain
    chain.update.return_value = chain
    chain.upsert.return_value = chain
    chain.delete.return_value = chain
    chain.eq.return_value = chain
    chain.neq.return_value = chain
    chain.in_.return_value = chain
    chain.gte.return_value = chain
    chain.lte.return_value = chain
    chain.not_.return_value = chain
    chain.is_.return_value = chain
    chain.order.return_value = chain
    chain.limit.return_value = chain
    chain.offset.return_value = chain
    return mock


@pytest.fixture()
def db_mock():
    """Supabase DB mock, available as a fixture."""
    return _make_supabase_mock()


@pytest.fixture()
def client(db_mock):
    """FastAPI TestClient with Supabase patched out."""
    with patch("main.get_db",       return_value=db_mock), \
         patch("main.get_admin_db", return_value=db_mock), \
         patch("supabase.create_client", return_value=db_mock):
        from fastapi.testclient import TestClient
        import main as app_module
        yield TestClient(app_module.app)


@pytest.fixture()
def admin_token(db_mock):
    """
    A fake Bearer token that passes get_user_from_header and is_admin.
    The sessions mock returns user_id='admin-uuid', and users mock returns ADMIN_EMAIL.
    """
    token = "test-admin-token-abc123"
    sessions_chain = MagicMock()
    sessions_chain.execute.return_value = MagicMock(data=[{"user_id": "admin-uuid"}])
    users_chain = MagicMock()
    users_chain.execute.return_value = MagicMock(data=[{"email": "admin@swarmhawk.com"}])

    def table_router(name):
        if name == "sessions": return sessions_chain
        if name == "users":    return users_chain
        return db_mock.table(name)

    db_mock.table.side_effect = table_router
    return f"Bearer {token}"


@pytest.fixture()
def user_token(db_mock):
    """A fake Bearer token for a regular (non-admin) user."""
    sessions_chain = MagicMock()
    sessions_chain.execute.return_value = MagicMock(data=[{"user_id": "user-uuid"}])
    users_chain = MagicMock()
    users_chain.execute.return_value = MagicMock(data=[{"email": "user@example.com"}])

    def table_router(name):
        if name == "sessions": return sessions_chain
        if name == "users":    return users_chain
        return db_mock.table(name)

    db_mock.table.side_effect = table_router
    return "Bearer test-user-token-xyz"
