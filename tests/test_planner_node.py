"""Unit tests for the Planner graph node."""

import pytest

from prism.graph.nodes.planner import create_planner_node
from prism.graph.state import PRState, ReviewPlan
from prism.models.factory import MockReviewLLM


@pytest.mark.asyncio
async def test_planner_node_success():
    expected_plan = ReviewPlan(
        summary="PR adds rate limiting middleware to prevent brute force attacks.",
        key_changes=["Add redis token bucket", "Hook into FastAPI middleware"],
        affected_components=["middleware", "auth"],
        security_critical=True,
        testing_concerns=["Verify burst traffic resilience"],
        specialist_guidance={
            "code_reviewer": "Check lock safety in token bucket implementation.",
            "security_reviewer": "Ensure IP spoofing via X-Forwarded-For is prevented.",
            "test_suggester": "Recommend test cases for concurrent requests.",
        },
    )

    mock_llm = MockReviewLLM(plan=expected_plan)
    planner = create_planner_node(mock_llm)

    state: PRState = {
        "repository": "test-org/test-repo",
        "pull_request_number": 10,
        "pr_metadata": {"title": "Add rate limiter", "body": "Uses redis"},
        "diff": "diff --git a/ratelimit.py b/ratelimit.py\n+class Limiter: pass",
        "changed_files": [{"filename": "ratelimit.py"}],
    }

    result = await planner(state)
    assert result["status"] == "PLANNED"
    assert "review_plan" in result
    plan_dict = result["review_plan"]
    assert plan_dict["security_critical"] is True
    assert plan_dict["summary"] == expected_plan.summary
    assert len(plan_dict["key_changes"]) == 2


@pytest.mark.asyncio
async def test_planner_node_fallback_on_model_error():
    # Simulate LLM raising an error when invoking structured output
    mock_llm = MockReviewLLM(error_on_schema=ReviewPlan)
    planner = create_planner_node(mock_llm)

    state: PRState = {
        "repository": "test-org/test-repo",
        "pull_request_number": 99,
        "pr_metadata": {"title": "Refactor auth tokens", "body": "JWT changes"},
        "diff": "+token = generate()",
        "changed_files": [{"filename": "auth/tokens.py"}],
    }

    result = await planner(state)
    assert result["status"] == "PLANNED_WITH_FALLBACK"
    assert "review_plan" in result
    assert "errors" in result
    assert len(result["errors"]) == 1
    assert "Planner node failed" in result["errors"][0]

    # Verify fallback plan correctly deduced security_critical from filename 'auth/tokens.py'
    plan_dict = result["review_plan"]
    assert plan_dict["security_critical"] is True
    assert "auth/tokens.py" in plan_dict["affected_components"]
