"""FastAPI route modules for PRism."""

from prism.api.routes.approvals import router as approvals_router
from prism.api.routes.dashboard import router as dashboard_router
from prism.api.routes.health import router as health_router
from prism.api.routes.reviews import router as reviews_router
from prism.api.routes.webhook import router as webhook_router

__all__ = [
    "approvals_router",
    "dashboard_router",
    "health_router",
    "reviews_router",
    "webhook_router",
]
