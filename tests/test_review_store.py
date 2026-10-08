"""Unit tests for SQLite ReviewStore."""

import tempfile

import pytest

from prism.services.models import (
    PublishedReviewRecord,
    ReviewRecord,
    ReviewStatus,
    WebhookDeliveryRecord,
)
from prism.storage.review_store import ReviewStore


@pytest.fixture
def temp_store():
    with tempfile.NamedTemporaryFile(suffix=".db") as tmp:
        store = ReviewStore(db_path=tmp.name)
        yield store


@pytest.mark.asyncio
async def test_store_initialization(temp_store):
    await temp_store.initialize()
    # Initializing a second time is idempotent
    await temp_store.initialize()


@pytest.mark.asyncio
async def test_record_delivery_idempotency(temp_store):
    delivery = WebhookDeliveryRecord(
        delivery_id="deliv-12345",
        event="pull_request",
        action="opened",
        repository="octocat/Hello-World",
        pull_number=1,
    )

    # First insert succeeds
    is_new = await temp_store.record_delivery(delivery)
    assert is_new is True

    # Duplicate delivery rejected
    is_duplicate = await temp_store.record_delivery(delivery)
    assert is_duplicate is False

    fetched = await temp_store.get_delivery("deliv-12345")
    assert fetched is not None
    assert fetched.delivery_id == "deliv-12345"
    assert fetched.repository == "octocat/Hello-World"


@pytest.mark.asyncio
async def test_save_and_get_review(temp_store):
    record = ReviewRecord(
        review_id="rev-001",
        repository="octocat/Hello-World",
        pull_number=42,
        head_sha="abcdef1234567890",
        status=ReviewStatus.WAITING_FOR_APPROVAL,
        risk_level="high",
        requires_human_approval=True,
        summary="Review found SQL injection",
        findings_count=1,
        critical_count=1,
        high_count=0,
        injection_detected=False,
        matched_rules=["RULE_AUTH_CODE"],
        policy_reasons=["Authentication module modified"],
        approval_status=None,
        thread_id="octocat/Hello-World#42",
        raw_findings=[
            {
                "category": "injection",
                "severity": "critical",
                "title": "SQL Injection",
                "file": "auth/login.py",
                "line": 15,
            }
        ],
    )

    await temp_store.save_review(record)

    fetched = await temp_store.get_review("rev-001")
    assert fetched is not None
    assert fetched.review_id == "rev-001"
    assert fetched.status == ReviewStatus.WAITING_FOR_APPROVAL
    assert fetched.risk_level == "high"
    assert fetched.requires_human_approval is True
    assert fetched.findings_count == 1
    assert fetched.matched_rules == ["RULE_AUTH_CODE"]
    assert len(fetched.raw_findings) == 1
    assert fetched.raw_findings[0]["title"] == "SQL Injection"


@pytest.mark.asyncio
async def test_update_existing_review(temp_store):
    record = ReviewRecord(
        review_id="rev-002",
        repository="octocat/Hello-World",
        pull_number=10,
        head_sha="sha1",
        status=ReviewStatus.WAITING_FOR_APPROVAL,
        thread_id="octocat/Hello-World#10",
    )
    await temp_store.save_review(record)

    # Update status to APPROVED
    record.status = ReviewStatus.APPROVED
    record.approval_status = "APPROVED"
    record.reviewer_notes = "Verified by SecOps"
    await temp_store.save_review(record)

    fetched = await temp_store.get_review("rev-002")
    assert fetched.status == ReviewStatus.APPROVED
    assert fetched.approval_status == "APPROVED"
    assert fetched.reviewer_notes == "Verified by SecOps"


@pytest.mark.asyncio
async def test_list_reviews(temp_store):
    for i in range(5):
        await temp_store.save_review(
            ReviewRecord(
                review_id=f"rev-{i}",
                repository="octocat/Hello-World",
                pull_number=i + 1,
                head_sha=f"sha{i}",
                status=ReviewStatus.APPROVED,
                thread_id=f"octocat/Hello-World#{i+1}",
            )
        )

    reviews = await temp_store.list_reviews(limit=3, offset=0)
    assert len(reviews) == 3

    reviews_page_2 = await temp_store.list_reviews(limit=3, offset=3)
    assert len(reviews_page_2) == 2


@pytest.mark.asyncio
async def test_published_reviews_uniqueness(temp_store):
    pub = PublishedReviewRecord(
        publication_id="pub-100",
        review_id="rev-100",
        repository="org/repo",
        pull_number=5,
        head_sha="commit_sha_xyz",
        summary_comment_id=987654,
        inline_comments_count=2,
    )

    success = await temp_store.record_publication(pub)
    assert success is True

    # Same commit cannot be published twice
    duplicate_pub = PublishedReviewRecord(
        publication_id="pub-101",
        review_id="rev-101",
        repository="org/repo",
        pull_number=5,
        head_sha="commit_sha_xyz",
    )
    duplicate_result = await temp_store.record_publication(duplicate_pub)
    assert duplicate_result is False

    existing = await temp_store.get_publication_for_commit("org/repo", 5, "commit_sha_xyz")
    assert existing is not None
    assert existing.publication_id == "pub-100"
    assert existing.summary_comment_id == 987654
