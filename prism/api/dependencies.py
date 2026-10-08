"""FastAPI dependencies: Signature verification, API key authentication, and service injection."""

import hashlib
import hmac
import logging
from typing import Annotated

from fastapi import Header, HTTPException, Request, status

from prism.config import get_settings
from prism.services.review_service import ReviewService
from prism.storage.review_store import ReviewStore

logger = logging.getLogger(__name__)

# Global instances for dependency injection
_review_store: ReviewStore | None = None
_review_service: ReviewService | None = None


def get_review_store() -> ReviewStore:
    """Provide singleton instance of ReviewStore."""
    global _review_store
    if _review_store is None:
        _review_store = ReviewStore()
    return _review_store


def get_review_service() -> ReviewService:
    """Provide singleton instance of ReviewService."""
    global _review_service
    if _review_service is None:
        _review_service = ReviewService(store=get_review_store())
    return _review_service


def set_review_service(service: ReviewService) -> None:
    """Override ReviewService instance (used for testing and dependency injection)."""
    global _review_service
    _review_service = service


def set_review_store(store: ReviewStore) -> None:
    """Override ReviewStore instance (used for testing)."""
    global _review_store
    _review_store = store


async def verify_github_signature(request: Request) -> bytes:
    """Verify GitHub webhook HMAC SHA-256 signature (X-Hub-Signature-256).

    Returns raw request bytes if valid, raises HTTP 401 if missing or invalid.
    Uses constant-time comparison (hmac.compare_digest) to prevent timing attacks.
    """
    settings = get_settings()
    secret = settings.github_webhook_secret

    # If secret is not configured in local development, permit request with warning
    if not secret:
        logger.warning(
            "GITHUB_WEBHOOK_SECRET is not configured; skipping HMAC verification (INSECURE DEV MODE)"
        )
        return await request.body()

    signature_header = request.headers.get("X-Hub-Signature-256")
    if not signature_header:
        logger.warning("Rejected webhook request: Missing X-Hub-Signature-256 header")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-Hub-Signature-256 header",
        )

    if not signature_header.startswith("sha256="):
        logger.warning("Rejected webhook request: Invalid signature format")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid signature prefix; expected sha256=",
        )

    expected_sig = signature_header[7:].strip()
    raw_body = await request.body()

    computed_sig = hmac.new(
        key=secret.encode("utf-8"),
        msg=raw_body,
        digestmod=hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(computed_sig, expected_sig):
        logger.warning("Rejected webhook request: Signature mismatch")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid webhook signature",
        )

    return raw_body


async def verify_prism_api_key(
    api_key: Annotated[str | None, Header(alias="X-PRISM-API-KEY")] = None,
) -> None:
    """Authenticate approval endpoints with optional PRISM API key.

    If PRISM_API_KEY is configured in settings, requests must provide matching X-PRISM-API-KEY.
    If PRISM_API_KEY is None, local development access is allowed.
    """
    settings = get_settings()
    configured_key = settings.prism_api_key

    if not configured_key:
        # Local development mode: no API key required
        return

    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing required X-PRISM-API-KEY header",
        )

    if not hmac.compare_digest(api_key.strip(), configured_key.strip()):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid X-PRISM-API-KEY",
        )
