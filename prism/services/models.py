"""Data models and lifecycle states for PRism review services and store."""

import json
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class ReviewStatus(str, Enum):
    """Lifecycle status of a Pull Request review execution."""

    RECEIVED = "RECEIVED"
    RUNNING = "RUNNING"
    WAITING_FOR_APPROVAL = "WAITING_FOR_APPROVAL"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    PUBLISHED = "PUBLISHED"
    FAILED = "FAILED"


class ApprovalDecision(str, Enum):
    """Strictly allowed human review decisions."""

    APPROVE = "approve"
    REJECT = "reject"


class ApprovalRequest(BaseModel):
    """Payload submitted to human approval API."""

    decision: ApprovalDecision
    notes: str = Field(default="", max_length=2000)


class ApprovalResponse(BaseModel):
    """Response returned by human approval API."""

    review_id: str
    status: ReviewStatus
    decision: str
    notes: str = ""
    published: bool = False
    message: str


class WebhookDeliveryRecord(BaseModel):
    """Audit record for processed GitHub webhook deliveries."""

    delivery_id: str
    event: str
    action: str | None = None
    repository: str
    pull_number: int
    status: str = "processed"
    received_at: str = Field(
        default_factory=lambda: datetime.now(UTC).isoformat()
    )


class PublishedReviewRecord(BaseModel):
    """Audit record of reviews published back to GitHub."""

    publication_id: str
    review_id: str
    repository: str
    pull_number: int
    head_sha: str
    summary_comment_id: int | None = None
    inline_comments_count: int = 0
    published_at: str = Field(
        default_factory=lambda: datetime.now(UTC).isoformat()
    )


class ReviewRecord(BaseModel):
    """Persistent metadata record for a PRism review execution."""

    review_id: str
    repository: str
    pull_number: int
    head_sha: str
    status: ReviewStatus = ReviewStatus.RECEIVED
    risk_level: str = "low"
    requires_human_approval: bool = False
    summary: str = ""
    findings_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    injection_detected: bool = False
    matched_rules: list[str] = Field(default_factory=list)
    policy_reasons: list[str] = Field(default_factory=list)
    approval_status: str | None = None
    reviewer_notes: str | None = None
    thread_id: str
    publication_id: str | None = None
    error_message: str | None = None
    raw_findings: list[dict[str, Any]] = Field(default_factory=list)
    created_at: str = Field(
        default_factory=lambda: datetime.now(UTC).isoformat()
    )
    updated_at: str = Field(
        default_factory=lambda: datetime.now(UTC).isoformat()
    )

    def to_sqlite_row(self) -> dict[str, Any]:
        """Serialize for SQLite storage."""
        return {
            "review_id": self.review_id,
            "repository": self.repository,
            "pull_number": self.pull_number,
            "head_sha": self.head_sha,
            "status": self.status.value,
            "risk_level": self.risk_level,
            "requires_human_approval": 1 if self.requires_human_approval else 0,
            "summary": self.summary,
            "findings_count": self.findings_count,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "injection_detected": 1 if self.injection_detected else 0,
            "matched_rules_json": json.dumps(self.matched_rules),
            "policy_reasons_json": json.dumps(self.policy_reasons),
            "approval_status": self.approval_status,
            "reviewer_notes": self.reviewer_notes,
            "thread_id": self.thread_id,
            "publication_id": self.publication_id,
            "error_message": self.error_message,
            "raw_findings_json": json.dumps(self.raw_findings),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_sqlite_row(cls, row: dict[str, Any]) -> "ReviewRecord":
        """Deserialize from SQLite dictionary row."""
        return cls(
            review_id=row["review_id"],
            repository=row["repository"],
            pull_number=row["pull_number"],
            head_sha=row["head_sha"],
            status=ReviewStatus(row["status"]),
            risk_level=row["risk_level"],
            requires_human_approval=bool(row["requires_human_approval"]),
            summary=row.get("summary") or "",
            findings_count=row.get("findings_count", 0),
            critical_count=row.get("critical_count", 0),
            high_count=row.get("high_count", 0),
            medium_count=row.get("medium_count", 0),
            low_count=row.get("low_count", 0),
            injection_detected=bool(row.get("injection_detected", 0)),
            matched_rules=json.loads(row.get("matched_rules_json") or "[]"),
            policy_reasons=json.loads(row.get("policy_reasons_json") or "[]"),
            approval_status=row.get("approval_status"),
            reviewer_notes=row.get("reviewer_notes"),
            thread_id=row["thread_id"],
            publication_id=row.get("publication_id"),
            error_message=row.get("error_message"),
            raw_findings=json.loads(row.get("raw_findings_json") or "[]"),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )
