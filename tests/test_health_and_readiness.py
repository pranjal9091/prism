import tempfile
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from prism.api.app import app
from prism.api.dependencies import get_review_store, set_review_service, set_review_store
from prism.config import Settings
from prism.storage.review_store import ReviewStore


@pytest.fixture(autouse=True)
def isolated_health_env():
    """Ensure a clean, isolated SQLite review store for health tests."""
    with tempfile.NamedTemporaryFile(suffix=".db") as tmp_store:
        store = ReviewStore(db_path=tmp_store.name)
        set_review_store(store)
        yield
        set_review_store(None)
        set_review_service(None)


def test_health_check_endpoint():
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200

    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "PRism"
    assert data["version"] == "0.1.0"
    assert data["database"] == "ok"
    assert data["observability"] in ("disabled", "enabled")
    assert "mcp_server" in data
    assert "checkpoint_db" in data


def test_readiness_probe_normal_state():
    client = TestClient(app)
    response = client.get("/ready")
    assert response.status_code == 200

    data = response.json()
    assert data["status"] == "ready"
    assert data["checks"]["review_store"] == "ok"
    assert data["checks"]["checkpoint_db"] == "ok"
    assert data["checks"]["config"] == "ok"
    assert data["errors"] == []


def test_readiness_probe_fails_when_store_inaccessible():
    store = get_review_store()
    with patch.object(store, "get_stats", new_callable=AsyncMock) as mock_stats:
        mock_stats.side_effect = RuntimeError("SQLite database file locked or disk corrupted")

        client = TestClient(app)
        response = client.get("/ready")
        assert response.status_code == 503

        data = response.json()
        assert data["status"] == "not_ready"
        assert data["checks"]["review_store"] == "failed"
        assert len(data["errors"]) > 0
        assert any("Review store database inaccessible" in err for err in data["errors"])


def test_production_configuration_validation():
    # 1. Development environment: missing secrets allowed
    dev_settings = Settings(
        environment="development",
        github_token=None,
        github_webhook_secret=None,
        auto_publish_reviews=True,
    )
    is_valid, errors = dev_settings.validate_production_readiness()
    assert is_valid is True
    assert len(errors) == 0

    # 2. Production environment: missing token when publishing is enabled
    prod_invalid_token = Settings(
        environment="production",
        github_token="",
        github_webhook_secret="whsec_12345",
        auto_publish_reviews=True,
    )
    is_valid, errors = prod_invalid_token.validate_production_readiness()
    assert is_valid is False
    assert any("GITHUB_TOKEN is required in production" in err for err in errors)

    # 3. Production environment: missing webhook secret
    prod_missing_secret = Settings(
        environment="production",
        github_token="ghp_testtoken",
        github_webhook_secret=None,
        auto_publish_reviews=True,
    )
    is_valid, errors = prod_missing_secret.validate_production_readiness()
    assert is_valid is False
    assert any("GITHUB_WEBHOOK_SECRET is mandatory in production" in err for err in errors)

    # 4. Production environment: valid setup
    prod_valid = Settings(
        environment="production",
        github_token="ghp_validtoken123",
        github_webhook_secret="whsec_validsecret123",
        auto_publish_reviews=True,
        langfuse_enabled=False,
    )
    is_valid, errors = prod_valid.validate_production_readiness()
    assert is_valid is True
    assert len(errors) == 0
