"""Deterministic prompt injection detector for GitHub PR content."""

import re
from typing import Any

from pydantic import BaseModel, Field


class InjectionDetectionResult(BaseModel):
    """Structured analysis produced by prompt injection detector."""

    detected: bool = False
    confidence: float = Field(ge=0.0, le=1.0, default=0.0)
    matched_patterns: list[str] = Field(default_factory=list)
    locations: list[dict[str, Any]] = Field(default_factory=list)


# Core regex patterns targeting known prompt-injection and jailbreak attack vectors
_INJECTION_PATTERNS = [
    # 1. Direct instruction override / reset
    (
        r"\b(?:ignore|disregard|forget|bypass)\s+(?:all\s+)?(?:previous|prior|above|system)\s+(?:instructions|rules|prompts|directives|guidelines)\b",
        "INSTRUCTION_OVERRIDE",
        0.95,
    ),
    (
        r"\bsystem\s+prompt\s+override\b",
        "SYSTEM_OVERRIDE",
        0.95,
    ),
    # 2. Persona hijacking / roleplay
    (
        r"\byou\s+are\s+now\s+(?:an?|the\s+)?(?:repository\s+)?(?:admin|root|owner|superadmin|lead\s+reviewer|unrestricted|jailbroken)\b",
        "PERSONA_HIJACKING",
        0.90,
    ),
    (
        r"\bact\s+as\s+(?:an?|the\s+)?(?:repository\s+)?(?:admin|root|owner|superadmin|unrestricted\s+ai|jailbroken)\b",
        "PERSONA_HIJACKING",
        0.85,
    ),
    # 3. Prompt leakage / instruction exfiltration
    (
        r"\b(?:reveal|print|display|dump|repeat|show)\s+(?:your\s+)?(?:hidden\s+)?(?:system\s+)?(?:prompt|instructions|rules|developer\s+prompt)\b",
        "PROMPT_LEAK_ATTEMPT",
        0.90,
    ),
    (
        r"\bwhat\s+are\s+your\s+(?:exact\s+)?(?:system\s+)?instructions\b",
        "PROMPT_LEAK_ATTEMPT",
        0.80,
    ),
    # 4. Review manipulation & fake approvals
    (
        r"\b(?:approve\s+this\s+pr|mark\s+this\s+(?:pr|change|code)\s+as\s+safe|output\s+only\s+lgtm|report\s+no\s+(?:bugs|vulnerabilities|issues))\b",
        "TRIAGE_MANIPULATION",
        0.90,
    ),
    (
        r"\bdo\s+not\s+report\s+(?:any\s+)?(?:bugs|vulnerabilities|security\s+issues|flaws)\b",
        "TRIAGE_MANIPULATION",
        0.95,
    ),
    # 5. Delimiter breakout attempts
    (
        r"<\s*/?\s*(?:untrusted_input|system|developer|instructions|prompt)\s*>",
        "DELIMITER_BREAKOUT",
        0.95,
    ),
]

# Regex detecting code declaration syntax to prevent naive false positives on identifiers
_CODE_DECLARATION_RE = re.compile(
    r"^\s*(?:def\s+|class\s+|var\s+|let\s+|const\s+|function\s+)[a-zA-Z0-9_]+\s*(?:\(|=)"
)


def detect_prompt_injection(
    targets: dict[str, str],
) -> InjectionDetectionResult:
    """Analyze text sources for adversarial prompt injection patterns.

    Scans title, description, diff, and filenames. Accounts for code declarations
    to avoid spurious false positives on benign code identifiers.
    """
    matched_patterns: set[str] = set()
    locations: list[dict[str, Any]] = []
    max_confidence = 0.0

    for source, text in targets.items():
        if not text:
            continue

        lines = text.splitlines()
        for line_num, line in enumerate(lines, 1):
            clean_line = line.strip()
            if not clean_line:
                continue

            for pattern, pattern_name, base_confidence in _INJECTION_PATTERNS:
                match = re.search(pattern, clean_line, flags=re.IGNORECASE)
                if match:
                    # Check if this match is just a benign code declaration (e.g. `def ignore_previous_instructions():`)
                    is_code_declaration = bool(_CODE_DECLARATION_RE.match(clean_line))

                    if is_code_declaration:
                        # Benign code identifier with matching name - do not trigger false alarm
                        continue

                    # If in a comment or prose or title, high confidence injection
                    confidence = base_confidence

                    matched_patterns.add(pattern_name)
                    locations.append(
                        {
                            "source": source,
                            "line": line_num,
                            "pattern": pattern_name,
                            "snippet": clean_line[:120],
                        }
                    )
                    max_confidence = max(max_confidence, confidence)

    detected = len(matched_patterns) > 0 and max_confidence >= 0.75

    return InjectionDetectionResult(
        detected=detected,
        confidence=round(max_confidence, 2) if detected else 0.0,
        matched_patterns=sorted(matched_patterns),
        locations=locations,
    )
