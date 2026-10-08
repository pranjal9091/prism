"""Guardrails node: Sanitizes untrusted PR content and detects prompt injections."""

import logging
from typing import Any

from prism.config import get_settings
from prism.graph.state import PRState
from prism.guardrails.injection_detector import detect_prompt_injection
from prism.guardrails.sanitizer import sanitize_untrusted_text

logger = logging.getLogger(__name__)


def create_guardrails_node():
    """Factory creating the guardrails node."""

    async def guardrails_node(state: PRState) -> dict[str, Any]:
        settings = get_settings()
        meta = state.get("pr_metadata", {})
        diff = state.get("diff", "")

        raw_title = meta.get("title", "")
        raw_body = meta.get("body", "")

        # 1. Sanitize untrusted text fields into delimited XML representations
        sanitized_title = sanitize_untrusted_text(raw_title, source="pr_title", max_chars=1_000)
        sanitized_body = sanitize_untrusted_text(raw_body, source="pr_body", max_chars=20_000)
        sanitized_diff = sanitize_untrusted_text(
            diff, source="diff", max_chars=settings.max_diff_characters
        )

        # 2. Run deterministic prompt injection detector across untrusted text fields
        detection_targets = {
            "pr_title": raw_title,
            "pr_body": raw_body,
            "diff": diff[:100_000],
        }
        injection_result = detect_prompt_injection(detection_targets)

        updates: dict[str, Any] = {
            "sanitized_diff": sanitized_diff.sanitized_content,
            "sanitized_metadata": {
                **meta,
                "title": sanitized_title.sanitized_content,
                "body": sanitized_body.sanitized_content,
                "sanitized_title": sanitized_title.sanitized_content,
                "sanitized_body": sanitized_body.sanitized_content,
            },
            "injection_detection": injection_result.model_dump(),
            "status": "GUARDRAILS_APPLIED",
        }

        if injection_result.detected:
            patterns = ", ".join(injection_result.matched_patterns)
            logger.warning("Adversarial prompt injection detected: %s", patterns)
            updates["guardrail_errors"] = [
                f"Suspicious prompt injection pattern detected ({patterns}); content isolated."
            ]

        return updates

    return guardrails_node
