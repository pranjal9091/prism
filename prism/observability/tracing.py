"""Observability service and Langfuse tracing abstraction for PR reviews."""

import logging
import time
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from prism.observability.config import ObservabilityConfig
from prism.observability.logging import redact_secrets

logger = logging.getLogger(__name__)


class ReviewTraceContext(BaseModel):
    """Context container tracking a single Pull Request review execution lifecycle."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    review_id: str
    thread_id: str
    repository: str
    pull_number: int
    head_sha: str
    start_time: float = Field(default_factory=time.perf_counter)
    metadata: dict[str, Any] = Field(default_factory=dict)
    stages: dict[str, dict[str, Any]] = Field(default_factory=dict)
    tokens: dict[str, Any] = Field(
        default_factory=lambda: {"input": 0, "output": 0, "total": 0, "provider": "mock"}
    )
    cost: str | float = "unavailable"
    trace_obj: Any = None


class ObservabilityService:
    """Non-blocking, fail-safe observability service mediating traces, spans, and metrics.

    Guarantees that any telemetry or network failure will NEVER crash or interrupt
    underlying review execution.
    """

    def __init__(self, config: ObservabilityConfig | None = None):
        self.config = config or ObservabilityConfig.from_settings()
        self.langfuse_client: Any = None

        if self.config.enabled:
            try:
                from langfuse import Langfuse

                self.langfuse_client = Langfuse(
                    public_key=self.config.public_key,
                    secret_key=self.config.secret_key,
                    host=self.config.host,
                )
                logger.info("Langfuse observability tracing initialized successfully.")
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "Failed to initialize Langfuse client; continuing with telemetry disabled: %s",
                    exc,
                )
                self.langfuse_client = None

    @property
    def is_enabled(self) -> bool:
        """Return True if Langfuse client is active and enabled."""
        return self.config.enabled and self.langfuse_client is not None

    def start_review_trace(
        self,
        review_id: str,
        repository: str,
        pull_number: int,
        head_sha: str,
        thread_id: str | None = None,
        author: str | None = None,
    ) -> ReviewTraceContext:
        """Initialize a top-level review trace."""
        t_id = thread_id or f"{repository}#{pull_number}"
        metadata = redact_secrets({
            "repository": repository,
            "pull_request_number": pull_number,
            "head_sha": head_sha,
            "thread_id": t_id,
            "author": author or "unknown",
            "environment": self.config.environment,
        })

        trace_context = ReviewTraceContext(
            review_id=review_id,
            thread_id=t_id,
            repository=repository,
            pull_number=pull_number,
            head_sha=head_sha,
            start_time=time.perf_counter(),
            metadata=metadata,
        )

        if self.is_enabled:
            try:
                trace_context.trace_obj = self.langfuse_client.trace(
                    name="PR Review",
                    id=review_id,
                    metadata=metadata,
                    tags=["pr-review", repository],
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning("Graceful telemetry warning: start_review_trace failed: %s", exc)

        return trace_context

    def record_stage(
        self,
        trace_context: ReviewTraceContext,
        stage: str,
        duration_ms: float,
        input_data: dict[str, Any] | None = None,
        output_data: dict[str, Any] | None = None,
        tokens: dict[str, Any] | None = None,
        model_name: str | None = None,
        cost: str | float | None = None,
    ) -> None:
        """Record execution duration and telemetry for a specific pipeline stage."""
        sanitized_input = redact_secrets(input_data) if input_data else {}
        sanitized_output = redact_secrets(output_data) if output_data else {}

        trace_context.stages[stage] = {
            "duration_ms": duration_ms,
            "model_name": model_name or "mock",
            "tokens": tokens or {"input": 0, "output": 0, "total": 0, "provider": "mock"},
            "cost": cost or "unavailable",
        }

        if self.is_enabled and trace_context.trace_obj:
            try:
                if tokens and model_name and model_name != "mock":
                    # Record generation span with token metrics
                    self.langfuse_client.generation(
                        trace_id=trace_context.review_id,
                        name=f"Stage: {stage}",
                        model=model_name,
                        input=sanitized_input,
                        output=sanitized_output,
                        usage=tokens,
                        metadata={"cost": cost or "unavailable"},
                    )
                else:
                    # Record general operational span
                    span = trace_context.trace_obj.span(
                        name=f"Stage: {stage}",
                        input=sanitized_input,
                        metadata={"duration_ms": duration_ms, "model": model_name or "mock"},
                    )
                    span.end(output=sanitized_output)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Graceful telemetry warning: record_stage failed on %s: %s", stage, exc)

    def end_review_trace(
        self,
        trace_context: ReviewTraceContext,
        status: str,
        risk_level: str | None = None,
        requires_human_approval: bool | None = None,
        injection_detected: bool | None = None,
        finding_count: int | None = None,
        error: str | None = None,
    ) -> None:
        """Finalize top-level review trace and update summary tags."""
        total_duration_ms = (time.perf_counter() - trace_context.start_time) * 1000.0
        trace_context.metadata.update({
            "status": status,
            "risk_level": risk_level or "unknown",
            "requires_human_approval": bool(requires_human_approval),
            "injection_detected": bool(injection_detected),
            "total_findings": finding_count or 0,
            "total_duration_ms": round(total_duration_ms, 2),
            "error": redact_secrets(error) if error else None,
        })

        if self.is_enabled and trace_context.trace_obj:
            try:
                self.langfuse_client.trace(
                    id=trace_context.review_id,
                    output={
                        "status": status,
                        "risk_level": risk_level,
                        "requires_human_approval": requires_human_approval,
                        "finding_count": finding_count,
                    },
                    metadata=trace_context.metadata,
                    tags=["pr-review", trace_context.repository, status.lower()],
                )
                self.flush()
            except Exception as exc:  # noqa: BLE001
                logger.warning("Graceful telemetry warning: end_review_trace failed: %s", exc)

    def flush(self) -> None:
        """Safely flush pending telemetry to remote Langfuse collector."""
        if self.is_enabled:
            try:
                self.langfuse_client.flush()
            except Exception as exc:  # noqa: BLE001
                logger.warning("Graceful telemetry warning: flush failed: %s", exc)


# Global singleton management
_observability_service: ObservabilityService | None = None


def get_observability_service() -> ObservabilityService:
    """Retrieve or lazily initialize the singleton ObservabilityService."""
    global _observability_service
    if _observability_service is None:
        _observability_service = ObservabilityService()
    return _observability_service


def set_observability_service(service: ObservabilityService | None) -> None:
    """Override singleton ObservabilityService (used for unit tests and mocks)."""
    global _observability_service
    _observability_service = service
