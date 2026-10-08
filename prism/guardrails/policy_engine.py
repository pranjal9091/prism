"""Deterministic risk policy engine for Pull Request triage and human approval gating."""

import re
from dataclasses import dataclass
from enum import Enum

from pydantic import BaseModel, Field

from prism.graph.state import FindingCategory, PRState, Severity


class RiskLevel(str, Enum):
    """Overall calculated risk level of a Pull Request."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RiskDecision(BaseModel):
    """Deterministic evaluation decision specifying risk level and approval requirement."""

    risk_level: RiskLevel
    requires_human_approval: bool
    reasons: list[str] = Field(default_factory=list)
    matched_rules: list[str] = Field(default_factory=list)


@dataclass(frozen=True)
class PathPolicyRule:
    """Rule defining a sensitive file pattern triggering elevated risk."""

    rule_id: str
    category: str
    pattern: re.Pattern
    risk_level: RiskLevel
    reason_template: str


# Maintainable registry of sensitive filepath rules
SENSITIVE_PATH_RULES: list[PathPolicyRule] = [
    PathPolicyRule(
        rule_id="RULE_AUTH_CODE",
        category="Authentication & Authorization",
        pattern=re.compile(
            r"(?:^|/)(?:auth|authentication|authorization|security|oauth|jwt|permissions)(?:/|\..*$)",
            re.IGNORECASE,
        ),
        risk_level=RiskLevel.HIGH,
        reason_template="Authentication or security module modified: {filename}",
    ),
    PathPolicyRule(
        rule_id="RULE_DB_MIGRATION",
        category="Database Migrations",
        pattern=re.compile(
            r"(?:^|/)(?:migrations|alembic|db/migrate)(?:/|\..*$)|.*\.sql$",
            re.IGNORECASE,
        ),
        risk_level=RiskLevel.HIGH,
        reason_template="Database schema migration file modified: {filename}",
    ),
    PathPolicyRule(
        rule_id="RULE_SECRETS_CONFIG",
        category="Environment & Secrets",
        pattern=re.compile(
            r"(?:^|/)(?:\.env|\.env\..*|\w+\.secret|\w+\.pem|\w+\.key)$",
            re.IGNORECASE,
        ),
        risk_level=RiskLevel.CRITICAL,
        reason_template="Environment or secret credential file modified: {filename}",
    ),
    PathPolicyRule(
        rule_id="RULE_DEPENDENCY_MANIFEST",
        category="Dependency Manifests",
        pattern=re.compile(
            r"(?:^|/)(?:requirements.*\.txt|pyproject\.toml|package\.json|package-lock\.json|poetry\.lock|Cargo\.toml|go\.mod)$",
            re.IGNORECASE,
        ),
        risk_level=RiskLevel.HIGH,
        reason_template="Software dependency manifest modified: {filename}",
    ),
    PathPolicyRule(
        rule_id="RULE_CICD_WORKFLOW",
        category="CI/CD Workflows",
        pattern=re.compile(
            r"(?:^|/)(?:\.github/workflows/.*|\.gitlab-ci\.yml|Jenkinsfile)$",
            re.IGNORECASE,
        ),
        risk_level=RiskLevel.HIGH,
        reason_template="CI/CD workflow automation modified: {filename}",
    ),
    PathPolicyRule(
        rule_id="RULE_INFRASTRUCTURE",
        category="Infrastructure as Code",
        pattern=re.compile(
            r"(?:^|/)(?:Dockerfile.*|docker-compose.*|terraform/.*|\.tf|k8s/.*|kubernetes/.*)$",
            re.IGNORECASE,
        ),
        risk_level=RiskLevel.HIGH,
        reason_template="Container or cloud infrastructure definition modified: {filename}",
    ),
]

_SEVERITY_ORDER = {
    RiskLevel.LOW: 1,
    RiskLevel.MEDIUM: 2,
    RiskLevel.HIGH: 3,
    RiskLevel.CRITICAL: 4,
}


class DeterministicRiskPolicyEngine:
    """Zero-LLM deterministic policy engine.

    Evaluates file paths, findings severity, secret disclosures, and prompt injection
    indicators to establish risk level and enforce human approval boundaries.
    """

    @classmethod
    def evaluate(cls, state: PRState) -> RiskDecision:
        reasons: list[str] = []
        matched_rules: set[str] = set()
        highest_risk = RiskLevel.LOW

        def elevate_risk(level: RiskLevel):
            nonlocal highest_risk
            if _SEVERITY_ORDER[level] > _SEVERITY_ORDER[highest_risk]:
                highest_risk = level

        # 1. Inspect changed filepaths against sensitive path policies
        changed_files = state.get("changed_files", [])
        for f in changed_files:
            filename = f.get("filename", "")
            for rule in SENSITIVE_PATH_RULES:
                if rule.pattern.search(filename):
                    matched_rules.add(rule.rule_id)
                    reasons.append(rule.reason_template.format(filename=filename))
                    elevate_risk(rule.risk_level)

        # 2. Inspect aggregated findings for Critical and High severities
        aggregated_findings = state.get("aggregated_findings", [])
        for f in aggregated_findings:
            sev = f.get("severity", "").lower()
            cat = f.get("category", "")
            title = f.get("title", "Finding")
            filename = f.get("file", "unknown")

            if sev == Severity.CRITICAL.value:
                rule_id = "RULE_CRITICAL_FINDING"
                matched_rules.add(rule_id)
                reasons.append(f"Critical finding: '{title}' in {filename}")
                elevate_risk(RiskLevel.CRITICAL)

            elif sev == Severity.HIGH.value:
                rule_id = "RULE_HIGH_FINDING"
                matched_rules.add(rule_id)
                reasons.append(f"High severity finding: '{title}' in {filename}")
                elevate_risk(RiskLevel.HIGH)

            elif sev == Severity.MEDIUM.value:
                elevate_risk(RiskLevel.MEDIUM)

            # Explicit check for secret leak findings
            if cat == FindingCategory.SECRET_LEAK.value or "secret" in cat.lower():
                rule_id = "RULE_SECRET_LEAK_FINDING"
                matched_rules.add(rule_id)
                reasons.append(f"Possible credential exposure in {filename}")
                elevate_risk(RiskLevel.CRITICAL)

        # 3. Inspect Prompt Injection Detector signals
        injection_info = state.get("injection_detection", {})
        if injection_info.get("detected") is True:
            matched_rules.add("RULE_INJECTION_DETECTED")
            patterns = ", ".join(injection_info.get("matched_patterns", []))
            reasons.append(f"Adversarial prompt injection pattern detected ({patterns})")
            elevate_risk(RiskLevel.HIGH)

        # 4. Determine final human approval requirement
        # Human approval is required if risk is HIGH or CRITICAL, or if any policy rule triggered
        requires_approval = (
            highest_risk in (RiskLevel.HIGH, RiskLevel.CRITICAL) or len(matched_rules) > 0
        )

        return RiskDecision(
            risk_level=highest_risk,
            requires_human_approval=requires_approval,
            reasons=reasons,
            matched_rules=sorted(matched_rules),
        )
