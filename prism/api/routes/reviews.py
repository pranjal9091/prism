"""API endpoints for querying reviews and triggering local test reviews."""

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from prism.api.dependencies import get_review_service, get_review_store
from prism.services.models import ReviewRecord
from prism.services.review_service import ReviewService
from prism.storage.review_store import ReviewStore

router = APIRouter(prefix="/api/reviews", tags=["Reviews"])


class TestReviewRequest(BaseModel):
    """Payload to trigger an in-memory test PR review without requiring GitHub webhooks."""

    repository: str = Field(default="octocat/Hello-World")
    pull_number: int = Field(default=42, ge=1)
    title: str = Field(default="feat: optimize user login query", min_length=3)
    body: str = Field(default="Refactors authentication logic.", min_length=1)
    diff: str = Field(default="+ def login(): pass", min_length=1)
    changed_files: list[dict[str, Any]] = Field(
        default_factory=lambda: [{"filename": "auth/login.py", "status": "modified"}]
    )
    auto_publish: bool = Field(default=False)


@router.get("", response_model=list[ReviewRecord])
async def list_reviews(
    review_store: Annotated[ReviewStore, Depends(get_review_store)],
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[ReviewRecord]:
    """List recent PR reviews with pagination."""
    return await review_store.list_reviews(limit=limit, offset=offset)


@router.get("/{review_id}", response_model=ReviewRecord)
async def get_review_detail(
    review_id: str,
    review_store: Annotated[ReviewStore, Depends(get_review_store)],
) -> ReviewRecord:
    """Retrieve full details of a specific review execution."""
    review = await review_store.get_review(review_id)
    if not review:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Review '{review_id}' was not found.",
        )
    return review


@router.post("/test", response_model=ReviewRecord)
async def trigger_test_review(
    request: TestReviewRequest,
    review_service: Annotated[ReviewService, Depends(get_review_service)],
) -> ReviewRecord:
    """Trigger a review against in-memory fixture data for local development and demos."""
    return await review_service.execute_fixture_review(
        repository=request.repository,
        pull_number=request.pull_number,
        title=request.title,
        body=request.body,
        diff=request.diff,
        changed_files=request.changed_files,
        auto_publish=request.auto_publish,
    )
