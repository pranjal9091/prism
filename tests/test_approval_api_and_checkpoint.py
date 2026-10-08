"""Unit tests for approval API endpoints, API key authorization, and checkpoint resumption."""

import tempfile

import pytest
from fastapi.testclient import TestClient

from prism.api.app import create_app
from prism.api.dependencies import set_review_service, set_review_store
from prism.config import get_settings
from prism.models.factory import MockReviewLLM
from prism.services.models import ReviewStatus
from prism.services.review_publisher import ReviewPublisher
from prism.services.review_service import ReviewService
from prism.storage.review_store import ReviewStore
from tests.test_review_publisher import MockGitHubPublisherClient


@pytest.fixture
def test_env():
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
            "store": store,
            "service": service,
            "github_client": client,
        }


def test_health_endpoint(test_env):
    client = test_env["client"]
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "PRism"
    assert "version" in data


@pytest.mark.asyncio
async def test_approve_review_resumes_checkpoint_and_publishes(test_env):
    client = test_env["client"]
    service = test_env["service"]

    # 1. Create a high-risk review that pauses at the human approval gate
    review = await service.execute_fixture_review(
        repository="org/repo",
        pull_number=42,
        title="feat: update auth service",
        body="Refactors login tokens",
        diff="+ def verify(): pass",
        changed_files=[{"filename": "auth/tokens.py", "status": "modified"}],
        head_sha="head123",
        auto_publish=True,
    )
    assert review.status == ReviewStatus.WAITING_FOR_APPROVAL
    assert review.requires_human_approval is True

    # 2. Call approval endpoint
    response = client.post(
        f"/api/reviews/{review.review_id}/approve",
        json={"decision": "approve", "notes": "Approved by Security Lead"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "PUBLISHED"
    assert data["decision"] == "approve"
    assert data["published"] is True

    # 3. Verify store state was updated
    updated_review = await test_env["store"].get_review(review.review_id)
    assert updated_review.status == ReviewStatus.PUBLISHED
    assert updated_review.approval_status == "APPROVED"
    assert updated_review.reviewer_notes == "Approved by Security Lead"
    assert updated_review.publication_id is not None


@pytest.mark.asyncio
async def test_reject_review_resumes_checkpoint(test_env):
    client = test_env["client"]
    service = test_env["service"]

    review = await service.execute_fixture_review(
        repository="org/repo",
        pull_number=43,
        title="feat: update migration",
        body="Alters schema",
        diff="+ DROP TABLE users;",
        changed_files=[{"filename": "migrations/001.sql", "status": "modified"}],
        head_sha="head456",
        auto_publish=True,
    )
    assert review.status == ReviewStatus.WAITING_FOR_APPROVAL

    response = client.post(
        f"/api/reviews/{review.review_id}/reject",
        json={"decision": "reject", "notes": "Destructive migration rejected"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "REJECTED"
    assert data["decision"] == "reject"
    assert data["published"] is False

    updated_review = await test_env["store"].get_review(review.review_id)
    assert updated_review.status == ReviewStatus.REJECTED


def test_approval_api_key_enforcement(test_env, monkeypatch):
    monkeypatch.setenv("PRISM_API_KEY", "super_secret_prism_api_key")
    get_settings.cache_clear()
    client = test_env["client"]

    # Missing API key -> 401
    res1 = client.post(
        "/api/reviews/any_id/approve",
        json={"decision": "approve"},
    )
    assert res1.status_code == 401
    assert "Missing required X-PRISM-API-KEY" in res1.json()["detail"]

    # Wrong API key -> 401
    res2 = client.post(
        "/api/reviews/any_id/approve",
        headers={"X-PRISM-API-KEY": "wrong_key"},
        json={"decision": "approve"},
    )
    assert res2.status_code == 401
    assert "Invalid X-PRISM-API-KEY" in res2.json()["detail"]

    # Reset API key
    monkeypatch.delenv("PRISM_API_KEY", raising=False)
    get_settings.cache_clear()


def test_test_review_endpoint(test_env):
    client = test_env["client"]
    payload = {
        "repository": "test/sample-repo",
        "pull_number": 99,
        "title": "docs: update readme",
        "body": "Fixed typo",
        "diff": "+ Fixed typo in docs",
        "changed_files": [{"filename": "README.md", "status": "modified"}],
        "auto_publish": False,
    }

    response = client.post("/api/reviews/test", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["repository"] == "test/sample-repo"
    assert data["pull_number"] == 99
    assert data["risk_level"] == "low"
    assert data["status"] == "APPROVED"  # Low risk is auto-approved
