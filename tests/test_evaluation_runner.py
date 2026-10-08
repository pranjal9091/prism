"""Tests for offline benchmark scenario runner and deterministic model adapter."""

import os
from unittest.mock import patch

import pytest

from prism.evaluation.dataset import get_scenario_by_id
from prism.evaluation.runner import DeterministicBenchmarkLLM, execute_scenario
from prism.graph.state import (
    CodeReviewOutput,
    ReviewPlan,
    SecurityReviewOutput,
    TestSuggestionOutput,
)


@pytest.mark.asyncio
async def test_execute_benign_scenario_b01():
    scenario = get_scenario_by_id("B01")
    result = await execute_scenario(scenario, model_mode="mock")

    assert result.scenario_id == "B01"
    assert result.predicted_risk == "low"
    assert result.predicted_human_gate is False
    assert result.predicted_injection_detected is False
    assert result.execution_duration_ms > 0.0
    assert result.passed is True
    assert len(result.mismatches) == 0


@pytest.mark.asyncio
async def test_execute_code_quality_scenario_c01():
    scenario = get_scenario_by_id("C01")
    result = await execute_scenario(scenario, model_mode="mock")

    assert result.scenario_id == "C01"
    assert result.predicted_risk == "medium"
    assert result.predicted_human_gate is False
    assert len(result.predicted_findings) >= 1
    assert result.passed is True


@pytest.mark.asyncio
async def test_execute_security_scenario_s01():
    scenario = get_scenario_by_id("S01")
    result = await execute_scenario(scenario, model_mode="mock")

    assert result.scenario_id == "S01"
    assert result.predicted_risk == "high"
    assert result.predicted_human_gate is True
    assert "RULE_HIGH_FINDING" in result.predicted_policy_rules
    assert result.passed is True


@pytest.mark.asyncio
async def test_execute_critical_scenario_cr01():
    scenario = get_scenario_by_id("CR01")
    result = await execute_scenario(scenario, model_mode="mock")

    assert result.scenario_id == "CR01"
    assert result.predicted_risk == "critical"
    assert result.predicted_human_gate is True
    assert "RULE_CRITICAL_FINDING" in result.predicted_policy_rules
    assert "RULE_SECRET_LEAK_FINDING" in result.predicted_policy_rules
    assert result.passed is True


@pytest.mark.asyncio
async def test_execute_adversarial_scenario_a01():
    scenario = get_scenario_by_id("A01")
    result = await execute_scenario(scenario, model_mode="mock")

    assert result.scenario_id == "A01"
    assert result.predicted_injection_detected is True
    assert result.predicted_human_gate is True
    assert "RULE_INJECTION_DETECTED" in result.predicted_policy_rules
    assert result.passed is True


def test_deterministic_llm_adapter_structured_outputs():
    scenario = get_scenario_by_id("CR05")
    llm = DeterministicBenchmarkLLM(scenario)

    plan_runnable = llm.with_structured_output(ReviewPlan)
    plan = plan_runnable.invoke("prompt")
    assert isinstance(plan, ReviewPlan)
    assert plan.security_critical is True

    sec_runnable = llm.with_structured_output(SecurityReviewOutput)
    sec_out = sec_runnable.invoke("prompt")
    assert isinstance(sec_out, SecurityReviewOutput)
    assert len(sec_out.findings) >= 1

    code_runnable = llm.with_structured_output(CodeReviewOutput)
    code_out = code_runnable.invoke("prompt")
    assert isinstance(code_out, CodeReviewOutput)

    test_runnable = llm.with_structured_output(TestSuggestionOutput)
    test_out = test_runnable.invoke("prompt")
    assert isinstance(test_out, TestSuggestionOutput)


@pytest.mark.asyncio
async def test_live_mode_without_api_key_raises_error():
    scenario = get_scenario_by_id("B01")
    with (
        patch.dict(os.environ, {"OPENAI_API_KEY": ""}, clear=False),
        pytest.raises(ValueError, match="OPENAI_API_KEY environment variable required"),
    ):
        await execute_scenario(scenario, model_mode="live")
