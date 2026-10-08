"""Lightweight HTML dashboard and review detail UI routes using Jinja2."""

from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, Form, HTTPException, Request, responses, status
from fastapi.templating import Jinja2Templates

from prism.api.dependencies import get_review_service, get_review_store
from prism.services.models import ApprovalDecision, ReviewStatus
from prism.services.review_service import ReviewService
from prism.storage.review_store import ReviewStore

router = APIRouter(tags=["Dashboard"])

# Templates directory relative to this file
TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


@router.get("/", response_class=responses.HTMLResponse)
async def dashboard_index(
    request: Request,
    review_store: Annotated[ReviewStore, Depends(get_review_store)],
):
    """Render main triage dashboard with review summary cards and recent executions."""
    reviews = await review_store.list_reviews(limit=50)

    stats = {
        "total": len(reviews),
        "waiting_approval": sum(1 for r in reviews if r.status == ReviewStatus.WAITING_FOR_APPROVAL),
        "high_risk": sum(1 for r in reviews if r.risk_level in ("high", "critical")),
        "published": sum(1 for r in reviews if r.status == ReviewStatus.PUBLISHED),
    }

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "reviews": reviews,
            "stats": stats,
        },
    )


@router.get("/reviews/{review_id}", response_class=responses.HTMLResponse)
async def review_detail(
    request: Request,
    review_id: str,
    review_store: Annotated[ReviewStore, Depends(get_review_store)],
):
    """Render detailed view of a single review execution."""
    review = await review_store.get_review(review_id)
    if not review:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Review '{review_id}' was not found.",
        )

    return templates.TemplateResponse(
        request=request,
        name="review_detail.html",
        context={
            "review": review,
        },
    )


@router.post("/reviews/{review_id}/action", response_class=responses.RedirectResponse)
async def handle_dashboard_approval_action(
    review_id: str,
    decision: Annotated[str, Form(...)],
    review_service: Annotated[ReviewService, Depends(get_review_service)],
    notes: Annotated[str, Form()] = "",
):
    """Handle approval or rejection submitted via the dashboard web UI."""
    try:
        appr_decision = ApprovalDecision(decision.lower().strip())
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid decision '{decision}'. Expected 'approve' or 'reject'.",
        )

    await review_service.process_approval(
        review_id=review_id,
        decision=appr_decision,
        notes=notes,
    )

    return responses.RedirectResponse(
        url=f"/reviews/{review_id}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.post("/reviews/demo", response_class=responses.RedirectResponse)
async def trigger_dashboard_demo(
    review_service: Annotated[ReviewService, Depends(get_review_service)],
):
    """Trigger a sample PR review from the dashboard UI to demonstrate the workflow."""
    demo_review = await review_service.execute_fixture_review(
        repository="prism-demo/auth-service",
        pull_number=101,
        title="feat: optimize login handler with raw SQL query",
        body="Replaces ORM query with f-string formatted raw SQL for database performance.",
        diff=(
            "@@ -15,5 +15,6 @@\n"
            "+ def authenticate(user, pwd):\n"
            "+     query = f\"SELECT * FROM users WHERE user = '{user}' AND pwd = '{pwd}'\"\n"
            "+     return db.execute(query)\n"
        ),
        changed_files=[{"filename": "auth/login.py", "status": "modified"}],
        auto_publish=False,
    )

    return responses.RedirectResponse(
        url=f"/reviews/{demo_review.review_id}",
        status_code=status.HTTP_303_SEE_OTHER,
    )
