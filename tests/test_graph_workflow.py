"""End-to-end integration tests for the PRism LangGraph review workflow."""

import pytest

from prism.graph.builder import build_review_graph, execute_pr_review, resume_pr_review
from prism.graph.state import (
    CodeReviewOutput,
    Finding,
    FindingCategory,
    ReviewPlan,
    SecurityReviewOutput,
    Severity,
    TestSuggestionOutput,
)
from prism.models.factory import MockReviewLLM


@pytest.fixture
def sample_pr_payload():
    return {
        "repository": "octocat/hello-world",
        "pull_request_number": 42,
        "pr_metadata": {
            "title": "feat: introduce JWT authentication",
            "body": "Replaces session cookies with JWT tokens.",
        },
        "diff": (
            "diff --git a/auth.py b/auth.py\n"
            "+def create_token(user):\n"
            "+    return jwt.encode({'user': user}, 'secret_key', algorithm='none')\n"
        ),
        "changed_files": [{"filename": "auth.py", "status": "modified"}],
    }


@pytest.fixture
def configured_mock_llm():
    plan = ReviewPlan(
        summary="PR implements JWT authentication in auth.py.",
        key_changes=["Replaced session cookies with JWT token generation"],
        affected_components=["auth"],
        security_critical=True,
        testing_concerns=["Validate token algorithm safety and expiration"],
        specialist_guidance={
            "code_reviewer": "Verify token signature generation parameters.",
            "security_reviewer": "CRITICAL: Check algorithm parameter in jwt.encode.",
            "test_suggester": "Recommend tests for none algorithm rejection.",
        },
    )

    code_finding = Finding(
        category=FindingCategory.MAINTAINABILITY,
        severity=Severity.LOW,
        title="Hardcoded secret key string in function body",
        description="The secret key string 'secret_key' is hardcoded inline.",
        file="auth.py",
        line=3,
        recommendation="Extract to settings or environment variable.",
        confidence=0.85,
    )

    sec_finding = Finding(
        category=FindingCategory.AUTH,
        severity=Severity.CRITICAL,
        title="Insecure JWT None algorithm allowed",
        description="Algorithm 'none' generates unsigned tokens vulnerable to forgery.",
        file="auth.py",
        line=3,
        recommendation="Enforce asymmetric RS256 or HS256 with strong key.",
        confidence=0.99,
    )

    test_finding = Finding(
        category=FindingCategory.TEST_GAP,
        severity=Severity.HIGH,
        title="Missing test asserting rejection of unsigned tokens",
        description="No test suite verifies that unsigned tokens are rejected.",
        file="auth.py",
        line=2,
        recommendation="Add unit test `test_verify_unsigned_token_rejected()`.",
        confidence=0.9,
    )

    return MockReviewLLM(
        plan=plan,
        code_output=CodeReviewOutput(findings=[code_finding]),
        security_output=SecurityReviewOutput(findings=[sec_finding]),
        test_output=TestSuggestionOutput(findings=[test_finding]),
    )


@pytest.mark.asyncio
async def test_full_graph_execution(sample_pr_payload, configured_mock_llm):
    """Verify that the full graph executes:

    START -> guardrails -> planner -> [code | security | test] -> aggregator -> policy -> human_gate -> END
    """
    final_state, graph, config = await execute_pr_review(
        repository=sample_pr_payload["repository"],
        pull_request_number=sample_pr_payload["pull_request_number"],
        pr_metadata=sample_pr_payload["pr_metadata"],
        diff=sample_pr_payload["diff"],
        changed_files=sample_pr_payload["changed_files"],
        llm=configured_mock_llm,
        return_control=True,
    )

    # 1. Verify Planner ran and created plan
    assert "review_plan" in final_state
    plan = final_state["review_plan"]
    assert plan["security_critical"] is True
    assert "JWT" in plan["summary"]

    # 2. Verify all 3 parallel specialists executed and populated their respective state keys
    assert len(final_state["code_findings"]) == 1
    assert final_state["code_findings"][0]["title"] == "Hardcoded secret key string in function body"

    assert len(final_state["security_findings"]) == 1
    assert final_state["security_findings"][0]["title"] == "Insecure JWT None algorithm allowed"

    assert len(final_state["test_findings"]) == 1
    assert final_state["test_findings"][0]["title"] == "Missing test asserting rejection of unsigned tokens"

    # 3. Verify Aggregator ran and merged findings from all three specialists
    aggregated = final_state["aggregated_findings"]
    assert len(aggregated) == 3

    # Check contributing specialists breakdown in summary
    summary = final_state["review_summary"]
    assert summary["total_findings"] == 3
    assert summary["contributing_specialists"]["code_reviewer_count"] == 1
    assert summary["contributing_specialists"]["security_reviewer_count"] == 1
    assert summary["contributing_specialists"]["test_suggester_count"] == 1

    # 4. Verify M3 Risk Policy and Human Gate triggered interrupt on critical auth PR
    assert final_state["risk_decision"]["requires_human_approval"] is True
    assert "RULE_AUTH_CODE" in final_state["risk_decision"]["matched_rules"]
    assert "__interrupt__" in final_state

    # 5. Verify Resuming with explicit human approval
    resumed_state = await resume_pr_review(
        graph,
        config["configurable"]["thread_id"],
        decision="approve",
        notes="Reviewed and approved by security lead.",
    )
    assert resumed_state["human_approval_status"] == "APPROVED"
    assert resumed_state["status"] == "APPROVED_BY_HUMAN"
    assert resumed_state["approval_metadata"]["notes"] == "Reviewed and approved by security lead."
    assert summary["contributing_specialists"]["code_reviewer_count"] == 1
    assert summary["contributing_specialists"]["security_reviewer_count"] == 1
    assert summary["contributing_specialists"]["test_suggester_count"] == 1


@pytest.mark.asyncio
async def test_parallel_branching_and_state_isolation(sample_pr_payload):
    """Verify that the three parallel branches execute independently and merge without race conditions."""
    mock_llm = MockReviewLLM(
        code_output=CodeReviewOutput(
            findings=[
                Finding(
                    category=FindingCategory.BUG,
                    severity=Severity.LOW,
                    title="Code Finding",
                    description="Code finding description",
                    file="a.py",
                    recommendation="Fix a",
                    confidence=0.8,
                )
            ]
        ),
        security_output=SecurityReviewOutput(
            findings=[
                Finding(
                    category=FindingCategory.SECURITY,
                    severity=Severity.MEDIUM,
                    title="Security Finding",
                    description="Security finding description",
                    file="b.py",
                    recommendation="Fix b",
                    confidence=0.9,
                )
            ]
        ),
        test_output=TestSuggestionOutput(
            findings=[
                Finding(
                    category=FindingCategory.TESTING,
                    severity=Severity.LOW,
                    title="Test Finding",
                    description="Test finding description",
                    file="c.py",
                    recommendation="Fix c",
                    confidence=0.7,
                )
            ]
        ),
    )

    graph = build_review_graph(llm=mock_llm)

    init_state = {
        "repository": "test/repo",
        "pull_request_number": 1,
        "diff": "+line",
        "changed_files": [{"filename": "a.py"}],
        "code_findings": [],
        "security_findings": [],
        "test_findings": [],
        "aggregated_findings": [],
        "errors": [],
    }

    result = await graph.ainvoke(init_state)

    # Prove each branch populated its own state key and aggregator synthesized all 3
    assert len(result["code_findings"]) == 1
    assert len(result["security_findings"]) == 1
    assert len(result["test_findings"]) == 1
    assert len(result["aggregated_findings"]) == 3


@pytest.mark.asyncio
async def test_graph_fault_tolerance_when_specialist_fails(sample_pr_payload):
    """Verify that when one specialist fails, other specialists still complete and aggregator succeeds."""
    failing_llm = MockReviewLLM(
        error_on_schema=SecurityReviewOutput,  # Security reviewer will fail
        code_output=CodeReviewOutput(
            findings=[
                Finding(
                    category=FindingCategory.BUG,
                    severity=Severity.LOW,
                    title="Code Finding",
                    description="Code finding description",
                    file="main.py",
                    recommendation="Fix bug",
                    confidence=0.8,
                )
            ]
        ),
        test_output=TestSuggestionOutput(
            findings=[
                Finding(
                    category=FindingCategory.TESTING,
                    severity=Severity.LOW,
                    title="Test Finding",
                    description="Test finding description",
                    file="main.py",
                    recommendation="Add test",
                    confidence=0.8,
                )
            ]
        ),
    )

    final_state = await execute_pr_review(
        repository=sample_pr_payload["repository"],
        pull_request_number=sample_pr_payload["pull_request_number"],
        pr_metadata=sample_pr_payload["pr_metadata"],
        diff=sample_pr_payload["diff"],
        changed_files=sample_pr_payload["changed_files"],
        llm=failing_llm,
    )

    # Security findings is empty due to error, but recorded in errors
    assert len(final_state["security_findings"]) == 0
    assert len(final_state["errors"]) >= 1
    assert any("Security Reviewer node failed" in err for err in final_state["errors"])

    # Code and test findings are still collected
    assert len(final_state["code_findings"]) == 1
    assert len(final_state["test_findings"]) == 1

    # Aggregator still produces valid aggregated results
    assert final_state["status"] in ("COMPLETED", "POLICY_EVALUATED", "AGGREGATED")
    assert len(final_state["aggregated_findings"]) == 2
