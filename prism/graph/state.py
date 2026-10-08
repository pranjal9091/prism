"""State schemas and finding definitions for the PRism review graph."""

import operator
from enum import Enum
from typing import Annotated, Any

from pydantic import BaseModel, Field, field_validator
from typing_extensions import TypedDict


class Severity(str, Enum):
    """Normalized severity levels for triage findings."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingCategory(str, Enum):
    """Categorization of review findings."""

    CODE_QUALITY = "code_quality"
    BUG = "bug"
    MAINTAINABILITY = "maintainability"
    COMPLEXITY = "complexity"
    SECURITY = "security"
    SECRET_LEAK = "secret_leak"
    INJECTION = "injection"
    AUTH = "auth"
    TESTING = "testing"
    TEST_GAP = "test_gap"
    REGRESSION_RISK = "regression_risk"
    ARCHITECTURE = "architecture"


class Finding(BaseModel):
    """A strongly typed, structured finding identified by a specialist agent."""

    category: FindingCategory
    severity: Severity
    title: str = Field(min_length=3, max_length=150)
    description: str = Field(min_length=5)
    file: str = Field(min_length=1)
    line: int | None = Field(default=None, ge=1)
    recommendation: str = Field(min_length=5)
    confidence: float = Field(ge=0.0, le=1.0, description="Agent confidence score between 0.0 and 1.0")
    specialist: str | None = Field(
        default=None, description="Originating specialist agent (e.g., code_reviewer)"
    )

    @field_validator("title", "description", "file", "recommendation")
    @classmethod
    def strip_whitespace(cls, v: str) -> str:
        cleaned = v.strip()
        if not cleaned:
            raise ValueError("Field must not be empty or whitespace only.")
        return cleaned


class CodeReviewOutput(BaseModel):
    """Structured output schema for the Code Reviewer agent."""

    findings: list[Finding] = Field(default_factory=list)
    general_notes: str | None = None


class SecurityReviewOutput(BaseModel):
    """Structured output schema for the Security Reviewer agent."""

    findings: list[Finding] = Field(default_factory=list)
    threat_summary: str | None = None


class TestSuggestionOutput(BaseModel):
    """Structured output schema for the Test Suggester agent."""

    __test__ = False

    findings: list[Finding] = Field(default_factory=list)
    testing_strategy: str | None = None


class ReviewPlan(BaseModel):
    """Structured review plan produced by the Planner node."""

    summary: str = Field(min_length=5, description="High-level summary of the PR changes")
    key_changes: list[str] = Field(default_factory=list, description="List of primary functional changes")
    affected_components: list[str] = Field(
        default_factory=list, description="Subsystems or modules impacted by this PR"
    )
    security_critical: bool = Field(
        default=False, description="Flag indicating if PR touches auth, crypto, DB, or permissions"
    )
    testing_concerns: list[str] = Field(
        default_factory=list, description="Specific risk areas requiring test coverage"
    )
    specialist_guidance: dict[str, str] = Field(
        default_factory=dict,
        description="Targeted directives for code_reviewer, security_reviewer, and test_suggester",
    )


class AggregatedReviewResult(BaseModel):
    """Final aggregated synthesis produced by the aggregator node."""

    summary: str
    total_findings: int
    findings_by_severity: dict[str, int]
    findings: list[Finding]
    errors: list[str] = Field(default_factory=list)


class PRState(TypedDict, total=False):
    """Shared LangGraph state for PR review orchestration."""

    # Target PR Identifiers
    repository: str
    pull_request_number: int

    # Ingested PR Context
    pr_metadata: dict[str, Any]
    diff: str
    changed_files: list[dict[str, Any]]
    relevant_context: dict[str, Any]

    # Review Plan
    review_plan: dict[str, Any]

    # Specialist Agent Outputs (Separate keys prevent race conditions during fan-out)
    code_findings: list[dict[str, Any]]
    security_findings: list[dict[str, Any]]
    test_findings: list[dict[str, Any]]

    # Final Aggregation
    aggregated_findings: list[dict[str, Any]]
    review_summary: dict[str, Any]

    # Guardrails & Sanitization
    sanitized_diff: str
    sanitized_metadata: dict[str, Any]
    injection_detection: dict[str, Any]
    guardrail_errors: Annotated[list[str], operator.add]

    # Deterministic Risk Policy
    risk_decision: dict[str, Any]

    # Human-in-the-Loop Approval Gating
    human_approval_status: str
    approval_metadata: dict[str, Any]

    # Execution telemetry and errors (errors uses add reducer for thread safety)
    execution_metadata: dict[str, Any]
    errors: Annotated[list[str], operator.add]
    status: str
