"""Structured JSON logging with automated credential redaction."""

import json
import logging
import re
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger("prism.structured")

# Compiled redaction patterns for common secret formats
_REDACT_PATTERNS = [
    # GitHub Tokens
    (re.compile(r"(?:ghp_[a-zA-Z0-9]{20,}|github_pat_[a-zA-Z0-9_]{20,})"), "[REDACTED_GITHUB_TOKEN]"),
    # OpenAI & Generic API keys
    (re.compile(r"sk-[a-zA-Z0-9_\-]{20,}"), "[REDACTED_API_KEY]"),
    # Bearer / Authorization headers
    (re.compile(r"(?i)(?:bearer\s+)[a-zA-Z0-9_\-\.]{20,}"), "Bearer [REDACTED_TOKEN]"),
    # Private Key blocks
    (
        re.compile(r"-----BEGIN[ A-Z0-9_-]+PRIVATE KEY-----.*?-----END[ A-Z0-9_-]+PRIVATE KEY-----", re.DOTALL),
        "[REDACTED_PRIVATE_KEY]",
    ),
    # Passwords in URLs (e.g., postgres://user:password@host)
    (re.compile(r"(?i)([a-z]+://[^:]+:)[^@]+(@)"), r"\1[REDACTED_PASSWORD]\2"),
]

_SENSITIVE_KEY_NAMES = {
    "token",
    "secret",
    "password",
    "api_key",
    "apikey",
    "authorization",
    "github_token",
    "webhook_secret",
    "langfuse_secret_key",
    "prism_api_key",
    "private_key",
}


def redact_string(val: str) -> str:
    """Scrub sensitive credentials and keys from a string value."""
    if not isinstance(val, str):
        return val
    redacted = val
    for pattern, replacement in _REDACT_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    return redacted


def redact_secrets(obj: Any) -> Any:
    """Recursively scrub secrets from strings, dictionaries, and iterables."""
    if isinstance(obj, str):
        return redact_string(obj)

    if isinstance(obj, dict):
        cleaned: dict[str, Any] = {}
        for k, v in obj.items():
            k_lower = str(k).lower().strip()
            is_token_metric = (
                any(
                    metric in k_lower
                    for metric in (
                        "token_usage",
                        "total_tokens",
                        "input_tokens",
                        "output_tokens",
                        "tokens_used",
                    )
                )
                or k_lower == "tokens"
            )
            if not is_token_metric and any(sens in k_lower for sens in _SENSITIVE_KEY_NAMES):
                cleaned[k] = "[REDACTED]"
            else:
                cleaned[k] = redact_secrets(v)
        return cleaned

    if isinstance(obj, list):
        return [redact_secrets(item) for item in obj]

    if isinstance(obj, tuple):
        return tuple(redact_secrets(item) for item in obj)

    return obj


class StructuredLogFormatter(logging.Formatter):
    """Logging formatter emitting single-line JSON records with redacted payloads."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": redact_secrets(record.getMessage()),
        }

        # Include custom structured attributes attached to LogRecord
        if hasattr(record, "structured_data") and isinstance(record.structured_data, dict):
            for k, v in record.structured_data.items():
                payload[k] = redact_secrets(v)

        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)

        return json.dumps(payload, default=str)


def log_event(event: str, level: str = "INFO", **kwargs: Any) -> dict[str, Any]:
    """Emit a structured, secret-redacted log record."""
    sanitized_kwargs = redact_secrets(kwargs)
    entry = {
        "timestamp": datetime.now(UTC).isoformat(),
        "level": level.upper(),
        "event": event,
        **sanitized_kwargs,
    }

    log_level = getattr(logging, level.upper(), logging.INFO)
    logger.log(log_level, json.dumps(entry, default=str))
    return entry
