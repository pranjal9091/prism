"""Unit tests for PRism graph state models and Finding validation."""

import pytest
from pydantic import ValidationError

from prism.graph.state import (
    CodeReviewOutput,
    Finding,
    FindingCategory,
    ReviewPlan,
    SecurityReviewOutput,
    Severity,
    TestSuggestionOutput,
)


def test_valid_finding_creation():
    finding = Finding(
        category=FindingCategory.BUG,
        severity=Severity.HIGH,
        title="Null pointer dereference in auth handler",
        description="User object may be None if session is expired, leading to AttributeError.",
        file="auth/handler.py",
        line=42,
        recommendation="Add `if user is None: return Unauthorized()` check.",
        confidence=0.95,
        specialist="code_reviewer",
    )
    assert finding.category == FindingCategory.BUG
    assert finding.severity == Severity.HIGH
    assert finding.title == "Null pointer dereference in auth handler"
    assert finding.file == "auth/handler.py"
    assert finding.line == 42
    assert finding.confidence == 0.95
    assert finding.specialist == "code_reviewer"


def test_finding_whitespace_stripping():
    finding = Finding(
        category=FindingCategory.SECURITY,
        severity=Severity.CRITICAL,
        title="  Hardcoded API key detected  ",
        description="  Secret key embedded in codebase.  ",
        file="  config.py  ",
        recommendation="  Move to environment variable.  ",
        confidence=1.0,
    )
    assert finding.title == "Hardcoded API key detected"
    assert finding.description == "Secret key embedded in codebase."
    assert finding.file == "config.py"
    assert finding.recommendation == "Move to environment variable."


@pytest.mark.parametrize(
    "invalid_confidence",
    [-0.1, 1.1, 2.0, -10.0],
)
def test_finding_invalid_confidence_rejected(invalid_confidence: float):
    with pytest.raises(ValidationError):
        Finding(
            category=FindingCategory.BUG,
            severity=Severity.LOW,
            title="Valid title",
            description="Valid description",
            file="file.py",
            recommendation="Valid recommendation",
            confidence=invalid_confidence,
        )


@pytest.mark.parametrize(
    "empty_val",
    ["", "   "],
)
def test_finding_empty_fields_rejected(empty_val: str):
    with pytest.raises(ValidationError):
        Finding(
            category=FindingCategory.BUG,
            severity=Severity.LOW,
            title=empty_val,
            description="Valid description",
            file="file.py",
            recommendation="Valid recommendation",
            confidence=0.5,
        )


def test_review_plan_validation():
    plan = ReviewPlan(
        summary="A comprehensive PR adding OAuth2 PKCE login support.",
        key_changes=["Added oauth.py", "Added pkce token exchange endpoint"],
        affected_components=["auth", "api"],
        security_critical=True,
        testing_concerns=["Verify token expiration edge cases"],
        specialist_guidance={
            "code_reviewer": "Check error propagation.",
            "security_reviewer": "Verify PKCE code challenge verification.",
            "test_suggester": "Suggest tests for expired codes.",
        },
    )
    assert plan.security_critical is True
    assert len(plan.key_changes) == 2
    assert len(plan.specialist_guidance) == 3


def test_specialist_container_outputs():
    code_out = CodeReviewOutput(findings=[])
    assert code_out.findings == []

    sec_out = SecurityReviewOutput(findings=[], threat_summary="No critical threats identified")
    assert sec_out.threat_summary == "No critical threats identified"

    test_out = TestSuggestionOutput(findings=[], testing_strategy="Unit test coverage required")
    assert test_out.testing_strategy == "Unit test coverage required"
