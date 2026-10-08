"""Health and readiness check endpoints."""

import os
from pathlib import Path

from fastapi import APIRouter, Response, status
from pydantic import BaseModel, Field

from prism.api.dependencies import get_review_store
from prism.config import get_settings
from prism.observability import get_observability_service

router = APIRouter(tags=["Health"])


class HealthResponse(BaseModel):
    """Liveness response payload."""

    status: str
    service: str
    version: str
    mcp_server: str
    checkpoint_db: str
    database: str = "ok"
    observability: str = "disabled"


class ReadinessResponse(BaseModel):
    """Readiness response payload."""

    status: str
    checks: dict[str, str]
    errors: list[str] = Field(default_factory=list)


@router.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    """Structured health check for service liveness."""
    settings = get_settings()
    obs = get_observability_service()
    obs_status = "enabled" if obs.is_enabled else "disabled"

    return HealthResponse(
        status="healthy",
        service="PRism",
        version="0.1.0",
        mcp_server=settings.mcp_server_name,
        checkpoint_db=settings.checkpoint_db_path,
        database="ok",
        observability=obs_status,
    )


@router.get("/ready", response_model=ReadinessResponse)
async def readiness_check(response: Response) -> ReadinessResponse:
    """Readiness probe checking database access, checkpoint storage, and configuration."""
    settings = get_settings()
    checks: dict[str, str] = {}
    errors: list[str] = []

    # 1. Probe Review SQLite Store
    try:
        store = get_review_store()
        await store.get_stats()
        checks["review_store"] = "ok"
    except Exception as exc:  # noqa: BLE001
        checks["review_store"] = "failed"
        errors.append(f"Review store database inaccessible: {exc}")

    # 2. Probe Checkpoint Database Access
    try:
        ckpt_path = Path(settings.checkpoint_db_path)
        parent_dir = ckpt_path.parent if str(ckpt_path.parent) != "" else Path(".")
        if not parent_dir.exists():
            parent_dir.mkdir(parents=True, exist_ok=True)
        if not os.access(parent_dir, os.W_OK):
            raise PermissionError(f"Directory '{parent_dir}' is not writable for checkpointing")
        checks["checkpoint_db"] = "ok"
    except Exception as exc:  # noqa: BLE001
        checks["checkpoint_db"] = "failed"
        errors.append(f"Checkpoint database inaccessible: {exc}")

    # 3. Check Production Configuration Requirements
    is_valid, config_errors = settings.validate_production_readiness()
    if is_valid:
        checks["config"] = "ok"
    else:
        checks["config"] = "invalid"
        errors.extend(config_errors)

    if errors:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return ReadinessResponse(status="not_ready", checks=checks, errors=errors)

    return ReadinessResponse(status="ready", checks=checks, errors=[])
