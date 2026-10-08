"""Unit tests for lightweight dashboard HTML routes."""

import tempfile

import pytest
from fastapi.testclient import TestClient

from prism.api.app import create_app
from prism.api.dependencies import set_review_service, set_review_store
from prism.models.factory import MockReviewLLM
from prism.services.models import ReviewRecord, ReviewStatus
from prism.services.review_publisher import ReviewPublisher
from prism.services.review_service import ReviewService
from prism.storage.review_store import ReviewStore
from tests.test_review_publisher import MockGitHubPublisherClient


@pytest.fixture
def dashboard_env():
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
        }


@pytest.mark.asyncio
async def test_dashboard_index_renders_html(dashboard_env):
    client = dashboard_env["client"]
    store = dashboard_env["store"]

    # Insert a review
    await store.save_review(
        ReviewRecord(
            review_id="rev-dash-1",
            repository="octocat/dashboard-demo",
            pull_number=10,
            head_sha="sha_dash_1",
            status=ReviewStatus.WAITING_FOR_APPROVAL,
            risk_level="high",
            thread_id="octocat/dashboard-demo#10",
        )
    )

    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    html = response.text
    assert "Pull Request Triage Dashboard" in html
    assert "octocat/dashboard-demo" in html
    assert "#10" in html
    assert "HIGH" in html


@pytest.mark.asyncio
async def test_review_detail_renders_and_handles_action(dashboard_env):
    client = dashboard_env["client"]
    service = dashboard_env["service"]

    # 1. Execute a high-risk review requiring approval
    review = await service.execute_fixture_review(
        repository="octocat/dashboard-demo",
        pull_number=11,
        title="feat: change credentials",
        body="Updating secret key",
        diff="+ SECRET_KEY = '123'",
        changed_files=[{"filename": ".env", "status": "modified"}],
    )

    # 2. View detail page
    detail_res = client.get(f"/reviews/{review.review_id}")
    assert detail_res.status_code == 200
    html = detail_res.text
    assert "Human Approval Gate: Explicit Decision Required" in html
    assert review.review_id in html

    # 3. Post approval from UI form
    action_res = client.post(
        f"/reviews/{review.review_id}/action",
        data={"decision": "approve", "notes": "Approved via UI"},
        follow_redirects=True,
    )
    assert action_res.status_code == 200
    updated_html = action_res.text
    assert "Approved by Human" in updated_html or "Published to GitHub" in updated_html


def test_dashboard_demo_action_redirects_to_detail(dashboard_env):
    client = dashboard_env["client"]
    res = client.post("/reviews/demo", follow_redirects=True)
    assert res.status_code == 200
    assert "Review Detail #" in res.text
    assert "prism-demo/auth-service" in res.text
