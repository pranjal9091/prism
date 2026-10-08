"""Unit tests for deterministic risk policy engine."""

from prism.graph.state import FindingCategory, PRState, Severity
from prism.guardrails.policy_engine import (
    DeterministicRiskPolicyEngine,
    RiskDecision,
    RiskLevel,
)


def create_base_state() -> PRState:
    return {
        "repository": "octocat/hello-world",
        "pull_request_number": 42,
        "pr_metadata": {"title": "Update documentation", "body": "Fixed typo", "author": "dev"},
        "diff": "+ # Documentation fix",
        "changed_files": [{"filename": "docs/readme.md", "status": "modified"}],
        "relevant_context": {},
        "code_findings": [],
        "security_findings": [],
        "test_findings": [],
        "aggregated_findings": [],
        "guardrail_errors": [],
        "errors": [],
        "status": "INITIALIZED",
    }


def test_benign_pr_low_risk_no_approval():
    state = create_base_state()
    decision = DeterministicRiskPolicyEngine.evaluate(state)
    assert isinstance(decision, RiskDecision)
    assert decision.risk_level == RiskLevel.LOW
    assert decision.requires_human_approval is False
    assert len(decision.reasons) == 0
    assert len(decision.matched_rules) == 0


def test_sensitive_path_auth_triggers_approval():
    state = create_base_state()
    state["changed_files"] = [{"filename": "src/auth/jwt_handler.py", "status": "modified"}]
    decision = DeterministicRiskPolicyEngine.evaluate(state)
    assert decision.risk_level == RiskLevel.HIGH
    assert decision.requires_human_approval is True
    assert "RULE_AUTH_CODE" in decision.matched_rules
    assert any("Authentication" in r for r in decision.reasons)


def test_sensitive_path_db_migration_triggers_approval():
    state = create_base_state()
    state["changed_files"] = [{"filename": "alembic/versions/001_create_users.py", "status": "added"}]
    decision = DeterministicRiskPolicyEngine.evaluate(state)
    assert decision.risk_level == RiskLevel.HIGH
    assert decision.requires_human_approval is True
    assert "RULE_DB_MIGRATION" in decision.matched_rules
    assert any("Database schema migration" in r for r in decision.reasons)


def test_sensitive_path_secret_env_triggers_critical():
    state = create_base_state()
    state["changed_files"] = [{"filename": ".env.production", "status": "modified"}]
    decision = DeterministicRiskPolicyEngine.evaluate(state)
    assert decision.risk_level == RiskLevel.CRITICAL
    assert decision.requires_human_approval is True
    assert "RULE_SECRETS_CONFIG" in decision.matched_rules
    assert any("Environment or secret credential" in r for r in decision.reasons)


def test_sensitive_path_dependency_manifest_triggers_approval():
    state = create_base_state()
    state["changed_files"] = [{"filename": "pyproject.toml", "status": "modified"}]
    decision = DeterministicRiskPolicyEngine.evaluate(state)
    assert decision.risk_level == RiskLevel.HIGH
    assert decision.requires_human_approval is True
    assert "RULE_DEPENDENCY_MANIFEST" in decision.matched_rules
    assert any("dependency manifest" in r for r in decision.reasons)


def test_sensitive_path_cicd_workflow_triggers_approval():
    state = create_base_state()
    state["changed_files"] = [{"filename": ".github/workflows/deploy.yml", "status": "modified"}]
    decision = DeterministicRiskPolicyEngine.evaluate(state)
    assert decision.risk_level == RiskLevel.HIGH
    assert decision.requires_human_approval is True
    assert "RULE_CICD_WORKFLOW" in decision.matched_rules
    assert any("CI/CD workflow" in r for r in decision.reasons)


def test_sensitive_path_infrastructure_triggers_approval():
    state = create_base_state()
    state["changed_files"] = [{"filename": "Dockerfile.prod", "status": "modified"}]
    decision = DeterministicRiskPolicyEngine.evaluate(state)
    assert decision.risk_level == RiskLevel.HIGH
    assert decision.requires_human_approval is True
    assert "RULE_INFRASTRUCTURE" in decision.matched_rules
    assert any("infrastructure definition" in r for r in decision.reasons)


def test_finding_critical_severity_elevates_risk():
    state = create_base_state()
    state["aggregated_findings"] = [
        {
            "category": FindingCategory.SECURITY.value,
            "severity": Severity.CRITICAL.value,
            "title": "Remote Code Execution",
            "description": "Unsanitized eval() of user input",
            "file": "server.py",
            "line_start": 42,
            "confidence": 0.95,
        }
    ]
    decision = DeterministicRiskPolicyEngine.evaluate(state)
    assert decision.risk_level == RiskLevel.CRITICAL
    assert decision.requires_human_approval is True
    assert "RULE_CRITICAL_FINDING" in decision.matched_rules
    assert any("Critical finding" in r for r in decision.reasons)


def test_finding_high_severity_elevates_risk():
    state = create_base_state()
    state["aggregated_findings"] = [
        {
            "category": FindingCategory.SECURITY.value,
            "severity": Severity.HIGH.value,
            "title": "SQL Injection",
            "description": "Raw string concatenation in query",
            "file": "db.py",
            "line_start": 10,
            "confidence": 0.9,
        }
    ]
    decision = DeterministicRiskPolicyEngine.evaluate(state)
    assert decision.risk_level == RiskLevel.HIGH
    assert decision.requires_human_approval is True
    assert "RULE_HIGH_FINDING" in decision.matched_rules


def test_finding_secret_leak_elevates_risk():
    state = create_base_state()
    state["aggregated_findings"] = [
        {
            "category": FindingCategory.SECRET_LEAK.value,
            "severity": Severity.MEDIUM.value,
            "title": "Hardcoded API Token",
            "description": "Hardcoded token in code",
            "file": "client.py",
            "line_start": 5,
            "confidence": 0.9,
        }
    ]
    decision = DeterministicRiskPolicyEngine.evaluate(state)
    assert decision.risk_level == RiskLevel.CRITICAL
    assert decision.requires_human_approval is True
    assert "RULE_SECRET_LEAK_FINDING" in decision.matched_rules


def test_injection_signal_elevates_risk():
    state = create_base_state()
    state["injection_detection"] = {
        "detected": True,
        "matched_patterns": ["INSTRUCTION_OVERRIDE"],
    }
    decision = DeterministicRiskPolicyEngine.evaluate(state)
    assert decision.risk_level == RiskLevel.HIGH
    assert decision.requires_human_approval is True
    assert "RULE_INJECTION_DETECTED" in decision.matched_rules
    assert any("Adversarial prompt injection pattern" in r for r in decision.reasons)


def test_multiple_matched_policies_collected():
    state = create_base_state()
    state["changed_files"] = [
        {"filename": "auth/token.py", "status": "modified"},
        {"filename": "alembic/migrations/v1.py", "status": "added"},
    ]
    state["aggregated_findings"] = [
        {
            "category": FindingCategory.SECURITY.value,
            "severity": Severity.CRITICAL.value,
            "title": "Bypass flaw",
            "file": "auth/token.py",
            "line_start": 1,
            "confidence": 0.99,
        }
    ]
    decision = DeterministicRiskPolicyEngine.evaluate(state)
    assert decision.risk_level == RiskLevel.CRITICAL
    assert decision.requires_human_approval is True
    assert "RULE_AUTH_CODE" in decision.matched_rules
    assert "RULE_DB_MIGRATION" in decision.matched_rules
    assert "RULE_CRITICAL_FINDING" in decision.matched_rules
    assert len(decision.reasons) >= 3


def test_deterministic_reproducibility():
    state = create_base_state()
    state["changed_files"] = [{"filename": "auth/token.py", "status": "modified"}]
    d1 = DeterministicRiskPolicyEngine.evaluate(state)
    d2 = DeterministicRiskPolicyEngine.evaluate(state)
    assert d1.model_dump() == d2.model_dump()
