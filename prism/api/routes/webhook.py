"""GitHub webhook receiver endpoint with signature verification and idempotency."""

import json
import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel

from prism.api.dependencies import get_review_service, get_review_store, verify_github_signature
from prism.services.models import WebhookDeliveryRecord
from prism.services.review_service import ReviewService
from prism.storage.review_store import ReviewStore

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/webhooks", tags=["Webhooks"])


# Strongly-typed subsets of GitHub Webhook Payload
class GitHubUserRef(BaseModel):
    login: str


class GitHubCommitRef(BaseModel):
    sha: str
    ref: str


class GitHubPullRequestPayload(BaseModel):
    number: int
    title: str
    body: str | None = ""
    html_url: str = ""
    head: GitHubCommitRef
    user: GitHubUserRef | None = None


class GitHubRepoPayload(BaseModel):
    full_name: str
    name: str


class GitHubWebhookPayload(BaseModel):
    action: str
    number: int | None = None
    pull_request: GitHubPullRequestPayload
    repository: GitHubRepoPayload
    sender: GitHubUserRef | None = None


class WebhookResponse(BaseModel):
    status: str
    message: str
    review_id: str | None = None
    repository: str | None = None
    pull_number: int | None = None
    risk_level: str | None = None
    delivery_id: str | None = None


SUPPORTED_ACTIONS = {"opened", "synchronize", "reopened"}


@router.post("/github", response_model=WebhookResponse)
async def handle_github_webhook(
    request: Request,
    raw_body: Annotated[bytes, Depends(verify_github_signature)],
    review_service: Annotated[ReviewService, Depends(get_review_service)],
    review_store: Annotated[ReviewStore, Depends(get_review_store)],
    x_github_event: Annotated[str | None, Header(alias="X-GitHub-Event")] = None,
    x_github_delivery: Annotated[str | None, Header(alias="X-GitHub-Delivery")] = None,
) -> WebhookResponse:
    """Handle incoming GitHub Pull Request webhooks with HMAC verification and delivery deduplication."""
    delivery_id = x_github_delivery or "unknown_delivery"
    event = (x_github_event or "pull_request").lower()

    # 1. Ping Event
    if event == "ping":
        logger.info("Received GitHub ping webhook")
        return WebhookResponse(
            status="ok",
            message="pong",
            delivery_id=delivery_id,
        )

    # 2. Only process pull_request events
    if event != "pull_request":
        logger.info("Ignoring unsupported GitHub event: %s", event)
        return WebhookResponse(
            status="ignored",
            message=f"Unsupported event type '{event}'",
            delivery_id=delivery_id,
        )

    # 3. Parse JSON Body
    try:
        data = json.loads(raw_body.decode("utf-8"))
        payload = GitHubWebhookPayload.model_validate(data)
    except (json.JSONDecodeError, ValueError) as exc:
        logger.warning("Invalid GitHub webhook JSON: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Malformed webhook payload: {exc}",
        ) from exc

    action = payload.action.lower()
    repo_slug = payload.repository.full_name
    pr_num = payload.pull_request.number

    # 4. Check Webhook Idempotency
    delivery_record = WebhookDeliveryRecord(
        delivery_id=delivery_id,
        event=event,
        action=action,
        repository=repo_slug,
        pull_number=pr_num,
        status="received",
    )
    is_new = await review_store.record_delivery(delivery_record)
    if not is_new:
        logger.info(
            "Duplicate webhook delivery detected (%s) for %s#%s. Skipping execution.",
            delivery_id,
            repo_slug,
            pr_num,
        )
        return WebhookResponse(
            status="ignored",
            message="Duplicate delivery identifier; already processed",
            delivery_id=delivery_id,
            repository=repo_slug,
            pull_number=pr_num,
        )

    # 5. Filter for supported PR actions
    if action not in SUPPORTED_ACTIONS:
        logger.info("Ignoring unsupported PR action: %s for %s#%s", action, repo_slug, pr_num)
        return WebhookResponse(
            status="ignored",
            message=f"Unsupported pull_request action '{action}'",
            delivery_id=delivery_id,
            repository=repo_slug,
            pull_number=pr_num,
        )

    logger.info("Processing webhook for %s#%s (action=%s)", repo_slug, pr_num, action)

    # 6. Execute Review Workflow
    try:
        review_record = await review_service.execute_review(
            repository=repo_slug,
            pull_number=pr_num,
        )
        return WebhookResponse(
            status="success",
            message=f"Review executed (Status: {review_record.status.value})",
            review_id=review_record.review_id,
            repository=repo_slug,
            pull_number=pr_num,
            risk_level=review_record.risk_level,
            delivery_id=delivery_id,
        )
    except Exception as exc:
        logger.exception("Review processing failed for %s#%s", repo_slug, pr_num)
        return WebhookResponse(
            status="failed",
            message=f"Review execution failed: {exc}",
            delivery_id=delivery_id,
            repository=repo_slug,
            pull_number=pr_num,
        )
