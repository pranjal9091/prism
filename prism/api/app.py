"""Main FastAPI application for PRism — Agentic GitHub PR Review & Triage System."""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from prism.api.dependencies import get_review_store
from prism.api.routes.approvals import router as approvals_router
from prism.api.routes.dashboard import router as dashboard_router
from prism.api.routes.health import router as health_router
from prism.api.routes.reviews import router as reviews_router
from prism.api.routes.webhook import router as webhook_router

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: initialize SQLite review store on boot."""
    logger.info("Initializing PRism SQLite review store...")
    store = get_review_store()
    await store.initialize()
    yield
    logger.info("PRism service shutting down.")


def create_app() -> FastAPI:
    """Factory creating configured PRism FastAPI application."""
    app = FastAPI(
        title="PRism — Agentic GitHub PR Review & Triage System",
        description="Autonomous multi-agent review, policy evaluation, and triage for GitHub Pull Requests.",
        version="0.1.0",
        lifespan=lifespan,
    )

    # CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Mount API routers
    app.include_router(health_router)
    app.include_router(webhook_router)
    app.include_router(approvals_router)
    app.include_router(reviews_router)
    app.include_router(dashboard_router)

    # Safe error response handler
    @app.exception_handler(Exception)
    async def global_exception_handler(request, exc):
        import uuid

        from fastapi.responses import JSONResponse

        from prism.observability import log_event

        request_id = request.headers.get("X-Request-ID") or f"req-{uuid.uuid4().hex[:8]}"
        log_event(
            "unhandled_server_error",
            level="ERROR",
            request_id=request_id,
            path=str(request.url.path),
            method=request.method,
            error_type=type(exc).__name__,
            error_message=str(exc),
        )
        return JSONResponse(
            status_code=500,
            content={
                "error": "internal_server_error",
                "message": "An unexpected error occurred during request processing.",
                "request_id": request_id,
            },
        )

    return app


app = create_app()
