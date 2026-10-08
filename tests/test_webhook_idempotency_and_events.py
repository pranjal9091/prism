"""Unit tests for GitHub webhook event routing and idempotency handling."""

import json
import tempfile

import pytest
from fastapi.testclient import TestClient

from prism.api.app import create_app
from prism.api.dependencies import set_review_service, set_review_store
from prism.config import get_settings
from prism.models.factory import MockReviewLLM
from prism.services.review_publisher import ReviewPublisher
from prism.services.review_service import ReviewService
from prism.storage.review_store import ReviewStore
from tests.test_review_publisher import MockGitHubPublisherClient
from tests.test_webhook_signatures import generate_signature


@pytest.fixture
def webhook_env(monkeypatch):
    secret = "secret_for_events_test"
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", secret)
    get_settings.cache_clear()

    with tempfile.NamedTemporaryFile(suffix=".db") as store_tmp, tempfile.NamedTemporaryFile(suffix=".db") as cp_tmp:
        store = ReviewStore(db_path=store_tmp.name)
        client = MockGitHubPublisherClient()
        publisher = ReviewPublisher(github_client=client, store=store)
        service = ReviewService(
            github_client=client,
            store=store,
            publisher=publisher,
            llm=MockReviewLLM(),
            checkpoint_db_path=cp_tmp.name,
        )

        set_review_store(store)
        set_review_service(service)

        app = create_app()
        test_client = TestClient(app)

        yield {
            "app": app,
            "client": test_client,
            "secret": secret,
            "store": store,
            "service": service,
        }


def make_pr_payload(action: str = "opened", pull_number: int = 10) -> dict:
    return {
        "action": action,
        "number": pull_number,
        "pull_request": {
            "number": pull_number,
            "title": "feat: update utils",
            "body": "Minor utils enhancement",
            "html_url": f"https://github.com/octocat/Hello-World/pull/{pull_number}",
            "head": {"sha": "headsha123", "ref": "feature-branch"},
            "user": {"login": "alice"},
        },
        "repository": {
            "full_name": "octocat/Hello-World",
            "name": "Hello-World",
        },
    }


def test_webhook_idempotency_prevents_duplicate_processing(webhook_env):
    client = webhook_env["client"]
    secret = webhook_env["secret"]

    payload = make_pr_payload(action="opened", pull_number=77)
    payload_bytes = json.dumps(payload).encode("utf-8")
    sig = generate_signature(secret, payload_bytes)
    delivery_id = "delivery_unique_999"

    headers = {
        "X-Hub-Signature-256": sig,
        "X-GitHub-Event": "pull_request",
        "X-GitHub-Delivery": delivery_id,
        "Content-Type": "application/json",
    }

    # First delivery
    res1 = client.post("/webhooks/github", content=payload_bytes, headers=headers)
    assert res1.status_code == 200
    assert res1.json()["status"] == "success"

    # Repeated delivery with exact same delivery_id
    res2 = client.post("/webhooks/github", content=payload_bytes, headers=headers)
    assert res2.status_code == 200
    assert res2.json()["status"] == "ignored"
    assert "Duplicate delivery" in res2.json()["message"]


def test_webhook_unsupported_action_safely_ignored(webhook_env):
    client = webhook_env["client"]
    secret = webhook_env["secret"]

    payload = make_pr_payload(action="labeled", pull_number=88)
    payload_bytes = json.dumps(payload).encode("utf-8")
    sig = generate_signature(secret, payload_bytes)

    headers = {
        "X-Hub-Signature-256": sig,
        "X-GitHub-Event": "pull_request",
        "X-GitHub-Delivery": "delivery_labeled_1",
        "Content-Type": "application/json",
    }

    res = client.post("/webhooks/github", content=payload_bytes, headers=headers)
    assert res.status_code == 200
    assert res.json()["status"] == "ignored"
    assert "Unsupported pull_request action 'labeled'" in res.json()["message"]


def test_webhook_unsupported_event_safely_ignored(webhook_env):
    client = webhook_env["client"]
    secret = webhook_env["secret"]

    payload_bytes = b'{"ref": "refs/heads/main"}'
    sig = generate_signature(secret, payload_bytes)

    headers = {
        "X-Hub-Signature-256": sig,
        "X-GitHub-Event": "push",
        "X-GitHub-Delivery": "delivery_push_1",
        "Content-Type": "application/json",
    }

    res = client.post("/webhooks/github", content=payload_bytes, headers=headers)
    assert res.status_code == 200
    assert res.json()["status"] == "ignored"
    assert "Unsupported event type 'push'" in res.json()["message"]
