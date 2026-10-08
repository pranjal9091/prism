"""Observability configuration schema and settings loader."""

import logging

from pydantic import BaseModel, Field

from prism.config import Settings, get_settings

logger = logging.getLogger(__name__)


class ObservabilityConfig(BaseModel):
    """Runtime configuration for Langfuse tracing and structured telemetry."""

    enabled: bool = Field(
        default=False,
        description="Flag indicating whether Langfuse tracing is active",
    )
    public_key: str | None = Field(
        default=None,
        description="Langfuse public API key",
    )
    secret_key: str | None = Field(
        default=None,
        description="Langfuse secret API key",
    )
    host: str = Field(
        default="https://cloud.langfuse.com",
        description="Langfuse service host endpoint",
    )
    environment: str = Field(
        default="development",
        description="Current runtime environment (development, staging, production)",
    )
    redact_sensitive_data: bool = Field(
        default=True,
        description="Whether to scrub tokens, credentials, and private keys from traces and logs",
    )

    @classmethod
    def from_settings(cls, settings: Settings | None = None) -> "ObservabilityConfig":
        """Construct ObservabilityConfig from global settings with graceful fallback."""
        s = settings or get_settings()

        enabled = bool(s.langfuse_enabled)
        public_key = s.langfuse_public_key
        secret_key = s.langfuse_secret_key
        host = s.langfuse_host or "https://cloud.langfuse.com"
        env = s.environment or "development"

        if enabled and (not public_key or not secret_key):
            logger.warning(
                "Langfuse credentials missing or incomplete; gracefully disabling observability tracing."
            )
            enabled = False

        return cls(
            enabled=enabled,
            public_key=public_key,
            secret_key=secret_key,
            host=host,
            environment=env,
            redact_sensitive_data=True,
        )
