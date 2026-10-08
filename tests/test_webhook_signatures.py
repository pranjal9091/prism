"""Unit tests for GitHub webhook HMAC-SHA256 signature verification."""

import hashlib
import hmac
import json

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from prism.api.routes.webhook import router as webhook_router
from prism.config import get_settings


@pytest.fixture
def test_webhook_app(monkeypatch):
    """Test app with configured webhook secret."""
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", "test_secret_12345")
    get_settings.cache_clear()

    app = FastAPI()
    app.include_router(webhook_router)
    return app


def generate_signature(secret: str, payload_bytes: bytes) -> str:
    """Compute sha256=... signature using secret."""
    digest = hmac.new(
        key=secret.encode("utf-8"),
        msg=payload_bytes,
        digestmod=hashlib.sha256,
    ).hexdigest()
    return f"sha256={digest}"


def test_valid_signature_accepted(test_webhook_app):
    client = TestClient(test_webhook_app)
    secret = "test_secret_12345"
    payload = {"zen": "Keep it logically awesome."}
    payload_bytes = json.dumps(payload).encode("utf-8")
    sig = generate_signature(secret, payload_bytes)

    response = client.post(
        "/webhooks/github",
        content=payload_bytes,
        headers={
            "X-Hub-Signature-256": sig,
            "X-GitHub-Event": "ping",
            "Content-Type": "application/json",
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["message"] == "pong"


def test_missing_signature_rejected(test_webhook_app):
    client = TestClient(test_webhook_app)
    payload_bytes = b'{"zen": "test"}'

    response = client.post(
        "/webhooks/github",
        content=payload_bytes,
        headers={
            "X-GitHub-Event": "ping",
            "Content-Type": "application/json",
        },
    )
    assert response.status_code == 401
    assert "Missing X-Hub-Signature-256" in response.json()["detail"]


def test_invalid_signature_rejected(test_webhook_app):
    client = TestClient(test_webhook_app)
    payload_bytes = b'{"zen": "test"}'

    response = client.post(
        "/webhooks/github",
        content=payload_bytes,
        headers={
            "X-Hub-Signature-256": "sha256=bad_hex_digest_000000000000000000000000",
            "X-GitHub-Event": "ping",
            "Content-Type": "application/json",
        },
    )
    assert response.status_code == 401
    assert "Invalid webhook signature" in response.json()["detail"]


def test_tampered_payload_rejected(test_webhook_app):
    client = TestClient(test_webhook_app)
    secret = "test_secret_12345"
    original_bytes = b'{"action": "opened"}'
    sig = generate_signature(secret, original_bytes)

    # Send tampered bytes with signature of original
    tampered_bytes = b'{"action": "opened", "malicious": true}'
    response = client.post(
        "/webhooks/github",
        content=tampered_bytes,
        headers={
            "X-Hub-Signature-256": sig,
            "X-GitHub-Event": "ping",
            "Content-Type": "application/json",
        },
    )
    assert response.status_code == 401
    assert "Invalid webhook signature" in response.json()["detail"]


def test_empty_body_with_valid_signature(test_webhook_app):
    client = TestClient(test_webhook_app)
    secret = "test_secret_12345"
    empty_bytes = b""
    sig = generate_signature(secret, empty_bytes)

    response = client.post(
        "/webhooks/github",
        content=empty_bytes,
        headers={
            "X-Hub-Signature-256": sig,
            "X-GitHub-Event": "ping",
            "Content-Type": "application/json",
        },
    )
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_invalid_signature_format_rejected(test_webhook_app):
    client = TestClient(test_webhook_app)
    payload_bytes = b'{"zen": "test"}'

    response = client.post(
        "/webhooks/github",
        content=payload_bytes,
        headers={
            "X-Hub-Signature-256": "md5=123456",
            "X-GitHub-Event": "ping",
            "Content-Type": "application/json",
        },
    )
    assert response.status_code == 401
    assert "Invalid signature prefix" in response.json()["detail"]
