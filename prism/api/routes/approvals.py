"""Human approval API routes for reviewing, resuming, and resolving reviews."""

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status

from prism.api.dependencies import get_review_service, verify_prism_api_key
from prism.services.models import (
    ApprovalDecision,
    ApprovalRequest,
    ApprovalResponse,
    ReviewStatus,
)
from prism.services.review_service import ReviewService

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/reviews", tags=["Approvals"])


@router.post("/{review_id}/approve", response_model=ApprovalResponse)
async def approve_review(
    review_id: str,
    request: ApprovalRequest,
    review_service: Annotated[ReviewService, Depends(get_review_service)],
    _auth: Annotated[None, Depends(verify_prism_api_key)] = None,
) -> ApprovalResponse:
    """Approve a review waiting at the human gate and trigger GitHub publishing."""
    if request.decision != ApprovalDecision.APPROVE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid decision for approval endpoint: expected 'approve', got '{request.decision}'",
        )

    try:
        updated = await review_service.process_approval(
            review_id=review_id,
            decision=ApprovalDecision.APPROVE,
            notes=request.notes,
        )
        return ApprovalResponse(
            review_id=updated.review_id,
            status=updated.status,
            decision="approve",
            notes=updated.reviewer_notes or "",
            published=updated.status == ReviewStatus.PUBLISHED,
            message="Review approved successfully and published to GitHub.",
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND if "not found" in str(exc).lower() else status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )
    except Exception as exc:
        logger.exception("Failed to approve review %s", review_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Approval resolution error: {exc}",
        )


@router.post("/{review_id}/reject", response_model=ApprovalResponse)
async def reject_review(
    review_id: str,
    request: ApprovalRequest,
    review_service: Annotated[ReviewService, Depends(get_review_service)],
    _auth: Annotated[None, Depends(verify_prism_api_key)] = None,
) -> ApprovalResponse:
    """Reject a review waiting at the human gate."""
    if request.decision != ApprovalDecision.REJECT:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid decision for rejection endpoint: expected 'reject', got '{request.decision}'",
        )

    try:
        updated = await review_service.process_approval(
            review_id=review_id,
            decision=ApprovalDecision.REJECT,
            notes=request.notes,
        )
        return ApprovalResponse(
            review_id=updated.review_id,
            status=updated.status,
            decision="reject",
            notes=updated.reviewer_notes or "",
            published=False,
            message="Review rejected by human reviewer.",
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND if "not found" in str(exc).lower() else status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )
    except Exception as exc:
        logger.exception("Failed to reject review %s", review_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Rejection resolution error: {exc}",
        )
