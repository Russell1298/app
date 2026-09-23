"""The browser's CORS preflight must accept every header the frontend sends."""
import importlib

import pytest
from fastapi.testclient import TestClient

ORIGIN = "https://siteguard-trust.lovable.app"


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("ALLOWED_ORIGINS", ORIGIN)
    import main
    return TestClient(importlib.reload(main).app)


def _preflight(client, origin, headers):
    return client.options("/api/v1/scan/full", headers={
        "Origin": origin,
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": headers,
    })


def test_preflight_accepts_the_ngrok_header_the_frontend_sends(client):
    r = _preflight(client, ORIGIN, "content-type,ngrok-skip-browser-warning,authorization")
    assert r.status_code == 200


def test_preflight_still_refuses_unlisted_origins(client):
    assert _preflight(client, "https://evil.example", "content-type").status_code == 400
