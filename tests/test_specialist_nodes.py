"""Unit tests for the three specialist agent nodes."""

import pytest

from prism.graph.nodes.code_reviewer import create_code_reviewer_node
from prism.graph.nodes.security_reviewer import create_security_reviewer_node
from prism.graph.nodes.test_suggester import create_test_suggester_node
from prism.graph.state import (
    CodeReviewOutput,
    Finding,
    FindingCategory,
    PRState,
    SecurityReviewOutput,
    Severity,
    TestSuggestionOutput,
)
from prism.models.factory import MockReviewLLM


@pytest.fixture
def base_state() -> PRState:
    return {
        "repository": "test-org/repo",
        "pull_request_number": 5,
        "diff": "diff --git a/app.py b/app.py\n+def run(): pass",
        "changed_files": [{"filename": "app.py"}],
        "review_plan": {
            "summary": "Review plan summary",
            "security_critical": False,
            "specialist_guidance": {
                "code_reviewer": "Check code structure.",
                "security_reviewer": "Check secrets.",
                "test_suggester": "Check tests.",
            },
        },
    }


# ==================== Code Reviewer Tests ====================


@pytest.mark.asyncio
async def test_code_reviewer_success(base_state):
    finding = Finding(
        category=FindingCategory.BUG,
        severity=Severity.HIGH,
        title="Uncaught TypeError in request parser",
        description="Parsing empty payload triggers unexpected TypeError.",
        file="app.py",
        line=12,
        recommendation="Check for None before attribute access.",
        confidence=0.9,
    )
    mock_llm = MockReviewLLM(code_output=CodeReviewOutput(findings=[finding]))
    node = create_code_reviewer_node(mock_llm)

    result = await node(base_state)
    assert "code_findings" in result
    assert len(result["code_findings"]) == 1
    f = result["code_findings"][0]
    assert f["title"] == "Uncaught TypeError in request parser"
    assert f["specialist"] == "code_reviewer"


@pytest.mark.asyncio
async def test_code_reviewer_empty(base_state):
    mock_llm = MockReviewLLM(code_output=CodeReviewOutput(findings=[]))
    node = create_code_reviewer_node(mock_llm)

    result = await node(base_state)
    assert result["code_findings"] == []


@pytest.mark.asyncio
async def test_code_reviewer_error_handling(base_state):
    mock_llm = MockReviewLLM(error_on_schema=CodeReviewOutput)
    node = create_code_reviewer_node(mock_llm)

    result = await node(base_state)
    assert result["code_findings"] == []
    assert len(result["errors"]) == 1
    assert "Code Reviewer node failed" in result["errors"][0]


# ==================== Security Reviewer Tests ====================


@pytest.mark.asyncio
async def test_security_reviewer_success(base_state):
    finding = Finding(
        category=FindingCategory.SECRET_LEAK,
        severity=Severity.CRITICAL,
        title="AWS Access Key exposed in configuration file",
        description="AKIA... access key detected directly committed in app.py.",
        file="app.py",
        line=2,
        recommendation="Revoke credential immediately and inject via environment.",
        confidence=0.99,
    )
    mock_llm = MockReviewLLM(security_output=SecurityReviewOutput(findings=[finding]))
    node = create_security_reviewer_node(mock_llm)

    result = await node(base_state)
    assert "security_findings" in result
    assert len(result["security_findings"]) == 1
    f = result["security_findings"][0]
    assert f["title"] == "AWS Access Key exposed in configuration file"
    assert f["specialist"] == "security_reviewer"


@pytest.mark.asyncio
async def test_security_reviewer_empty(base_state):
    mock_llm = MockReviewLLM(security_output=SecurityReviewOutput(findings=[]))
    node = create_security_reviewer_node(mock_llm)

    result = await node(base_state)
    assert result["security_findings"] == []


@pytest.mark.asyncio
async def test_security_reviewer_error_handling(base_state):
    mock_llm = MockReviewLLM(error_on_schema=SecurityReviewOutput)
    node = create_security_reviewer_node(mock_llm)

    result = await node(base_state)
    assert result["security_findings"] == []
    assert len(result["errors"]) == 1
    assert "Security Reviewer node failed" in result["errors"][0]


# ==================== Test Suggester Tests ====================


@pytest.mark.asyncio
async def test_test_suggester_success(base_state):
    finding = Finding(
        category=FindingCategory.TEST_GAP,
        severity=Severity.MEDIUM,
        title="Add regression test for timeout handling",
        description="Network retry loop is untested under simulated timeout conditions.",
        file="app.py",
        line=45,
        recommendation="Add `test_run_recovers_after_timeout()` using mock sleep.",
        confidence=0.85,
    )
    mock_llm = MockReviewLLM(test_output=TestSuggestionOutput(findings=[finding]))
    node = create_test_suggester_node(mock_llm)

    result = await node(base_state)
    assert "test_findings" in result
    assert len(result["test_findings"]) == 1
    f = result["test_findings"][0]
    assert f["title"] == "Add regression test for timeout handling"
    assert f["specialist"] == "test_suggester"


@pytest.mark.asyncio
async def test_test_suggester_empty(base_state):
    mock_llm = MockReviewLLM(test_output=TestSuggestionOutput(findings=[]))
    node = create_test_suggester_node(mock_llm)

    result = await node(base_state)
    assert result["test_findings"] == []


@pytest.mark.asyncio
async def test_test_suggester_error_handling(base_state):
    mock_llm = MockReviewLLM(error_on_schema=TestSuggestionOutput)
    node = create_test_suggester_node(mock_llm)

    result = await node(base_state)
    assert result["test_findings"] == []
    assert len(result["errors"]) == 1
    assert "Test Suggester node failed" in result["errors"][0]
