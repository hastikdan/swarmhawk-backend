"""Tests for health and basic infrastructure endpoints."""
import pytest


def test_health_returns_ok(client):
    r = client.get("/health")
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ok"
    assert "version" in data


def test_health_no_auth_required(client):
    """Health endpoint must be publicly accessible — no token needed."""
    r = client.get("/health")
    assert r.status_code != 401
    assert r.status_code != 403


def test_pipeline_status_public(client):
    """Pipeline status must be publicly accessible."""
    r = client.get("/pipeline/status")
    assert r.status_code == 200
    data = r.json()
    assert "total_domains" in data
    assert "queue_pending" in data
    assert "workers" in data


def test_map_data_public(client):
    """Map data endpoint must be publicly accessible."""
    r = client.get("/map/data")
    assert r.status_code == 200
