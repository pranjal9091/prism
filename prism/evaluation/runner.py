"""Evaluation runner and deterministic mock adapter for PRism benchmark."""

import asyncio
import os
import random
import time
from datetime import UTC, datetime
from typing import Any, TypeVar

from langchain_core.runnables import Runnable, RunnableLambda
from pydantic import BaseModel

from prism.evaluation.dataset import load_all_scenarios
from prism.evaluation.metrics import (
    calculate_benchmark_metrics,
    evaluate_findings_for_scenario,
)
from prism.evaluation.models import (
    BenchmarkReport,
    Scenario,
    ScenarioExecutionResult,
)
from prism.graph.builder import execute_pr_review
from prism.graph.state import (
    CodeReviewOutput,
    Finding,
    FindingCategory,
    ReviewPlan,
    SecurityReviewOutput,
    Severity,
    TestSuggestionOutput,
)
from prism.models.factory import get_llm

T = TypeVar("T", bound=BaseModel)


class DeterministicBenchmarkLLM:
    """Deterministic model adapter for reproducible benchmark execution.

    Synthesizes structured specialist outputs based on scenario characteristics
    without invoking any external or paid LLM APIs.
    """

    def __init__(self, scenario: Scenario):
        self.scenario = scenario

    def with_structured_output(self, schema: type[T]) -> Runnable[Any, T]:
        """Produce deterministic specialist outputs matching scenario design."""
        if issubclass(schema, ReviewPlan):
            response = ReviewPlan(
                summary=f"Evaluation plan for PR #{self.scenario.pr_number}: {self.scenario.title}",
                key_changes=[f.filename for f in self.scenario.files],
                affected_components=["benchmark"],
                security_critical=self.scenario.category in ("security", "critical"),
                testing_concerns=["behavioral correctness", "regression risk"],
                specialist_guidance={},
            )
            return RunnableLambda(lambda _: response)

        if issubclass(schema, CodeReviewOutput):
            code_findings = []
            for ef in self.scenario.ground_truth.expected_findings:
                if ef.category in ("bug", "code_quality", "maintainability", "complexity"):
                    code_findings.append(
                        Finding(
                            category=FindingCategory(ef.category),
                            severity=Severity(ef.severity),
                            title=ef.title,
                            description=f"Identified code quality issue in {ef.file}",
                            file=ef.file,
                            line=ef.approximate_line,
                            recommendation="Refactor code to resolve defect and improve safety.",
                            confidence=0.95,
                            specialist="code_reviewer",
                        )
                    )
            response = CodeReviewOutput(findings=code_findings)
            return RunnableLambda(lambda _: response)

        if issubclass(schema, SecurityReviewOutput):
            sec_findings = []
            for ef in self.scenario.ground_truth.expected_findings:
                if ef.category in ("security", "secret_leak", "injection", "auth"):
                    sec_findings.append(
                        Finding(
                            category=FindingCategory(ef.category),
                            severity=Severity(ef.severity),
                            title=ef.title,
                            description=f"Security risk identified in {ef.file}",
                            file=ef.file,
                            line=ef.approximate_line,
                            recommendation="Address security vulnerability immediately.",
                            confidence=0.98,
                            specialist="security_reviewer",
                        )
                    )
            response = SecurityReviewOutput(findings=sec_findings)
            return RunnableLambda(lambda _: response)

        if issubclass(schema, TestSuggestionOutput):
            test_findings = []
            for ef in self.scenario.ground_truth.expected_findings:
                if ef.category in ("test_gap", "testing", "regression_risk"):
                    test_findings.append(
                        Finding(
                            category=FindingCategory(ef.category),
                            severity=Severity(ef.severity),
                            title=ef.title,
                            description=f"Testing gap identified in {ef.file}",
                            file=ef.file,
                            line=ef.approximate_line,
                            recommendation="Add automated unit and regression tests.",
                            confidence=0.90,
                            specialist="test_suggester",
                        )
                    )
            response = TestSuggestionOutput(findings=test_findings)
            return RunnableLambda(lambda _: response)

        # Fallback empty instance
        return RunnableLambda(lambda _: schema())


async def execute_scenario(
    scenario: Scenario,
    model_mode: str = "mock",
) -> ScenarioExecutionResult:
    """Execute a single scenario through the complete PRism LangGraph review pipeline."""
    pr_metadata = {
        "title": scenario.title,
        "body": scenario.body,
        "author": scenario.author,
        "base_sha": scenario.base_sha,
        "head_sha": scenario.head_sha,
    }
    changed_files = [f.model_dump() for f in scenario.files]

    if model_mode == "mock":
        llm = DeterministicBenchmarkLLM(scenario)
    elif model_mode == "live":
        if not os.getenv("OPENAI_API_KEY"):
            raise ValueError("OPENAI_API_KEY environment variable required for live model mode.")
        llm = get_llm()
    else:
        raise ValueError(f"Unknown model mode: '{model_mode}'. Use 'mock' or 'live'.")

    start_time = time.perf_counter()

    result_state = await execute_pr_review(
        repository=scenario.repository,
        pull_request_number=scenario.pr_number,
        pr_metadata=pr_metadata,
        diff=scenario.diff,
        changed_files=changed_files,
        llm=llm,
        thread_id=f"eval-{scenario.scenario_id}-{int(start_time * 1000)}",
        return_control=False,
    )

    duration_ms = (time.perf_counter() - start_time) * 1000.0

    # Extract predicted telemetry
    risk_dec = result_state.get("risk_decision", {})
    raw_risk = risk_dec.get("risk_level", "low")
    pred_risk = raw_risk.value if hasattr(raw_risk, "value") else str(raw_risk)

    pred_findings = result_state.get("aggregated_findings", [])
    pred_categories = sorted({f.get("category", "") for f in pred_findings if f.get("category")})
    pred_rules = sorted(risk_dec.get("matched_rules", []))

    pred_injection = bool(result_state.get("injection_detection", {}).get("detected", False))
    pred_gate = bool(risk_dec.get("requires_human_approval", False) or "__interrupt__" in result_state)

    # Compare against ground truth
    gt = scenario.ground_truth
    risk_match = pred_risk.lower() == gt.expected_risk.lower()
    gate_match = pred_gate == gt.expected_human_gate
    inj_match = pred_injection == gt.expected_injection_detected
    rules_match = set(gt.expected_policy_rules).issubset(set(pred_rules))

    prec, rec, f1, _ = evaluate_findings_for_scenario(gt.expected_findings, pred_findings)

    mismatches: list[str] = []
    if not risk_match:
        mismatches.append(f"Risk mismatch: expected '{gt.expected_risk}', got '{pred_risk}'")
    if not gate_match:
        mismatches.append(f"Human gate mismatch: expected {gt.expected_human_gate}, got {pred_gate}")
    if not inj_match:
        mismatches.append(f"Injection mismatch: expected {gt.expected_injection_detected}, got {pred_injection}")
    if not rules_match:
        missing_rules = sorted(set(gt.expected_policy_rules) - set(pred_rules))
        mismatches.append(f"Missing expected policy rules: {missing_rules}")
    if f1 < 0.8:
        mismatches.append(f"Low finding F1: {round(f1, 3)} (precision={round(prec, 3)}, recall={round(rec, 3)})")

    passed = len(mismatches) == 0

    return ScenarioExecutionResult(
        scenario_id=scenario.scenario_id,
        category=scenario.category,
        title=scenario.title,
        predicted_risk=pred_risk,
        predicted_findings=pred_findings,
        predicted_categories=pred_categories,
        predicted_policy_rules=pred_rules,
        predicted_injection_detected=pred_injection,
        predicted_human_gate=pred_gate,
        execution_duration_ms=round(duration_ms, 2),
        passed=passed,
        risk_match=risk_match,
        human_gate_match=gate_match,
        injection_match=inj_match,
        policy_rules_match=rules_match,
        finding_precision=round(prec, 4),
        finding_recall=round(rec, 4),
        finding_f1=round(f1, 4),
        mismatches=mismatches,
    )


async def run_benchmark(
    scenarios: list[Scenario] | None = None,
    model_mode: str = "mock",
    seed: int = 42,
) -> BenchmarkReport:
    """Run evaluation benchmark across target scenarios and compute aggregated metrics."""
    random.seed(seed)
    active_scenarios = scenarios if scenarios is not None else load_all_scenarios()

    results: list[ScenarioExecutionResult] = []
    for sc in active_scenarios:
        res = await execute_scenario(sc, model_mode=model_mode)
        results.append(res)

    metrics = calculate_benchmark_metrics(active_scenarios, results)

    # Compile failure analysis
    failure_analysis: list[dict[str, Any]] = []
    for r in results:
        if not r.passed:
            sc = next(s for s in active_scenarios if s.scenario_id == r.scenario_id)
            failure_analysis.append(
                {
                    "scenario_id": r.scenario_id,
                    "title": r.title,
                    "expected": {
                        "risk": sc.ground_truth.expected_risk,
                        "human_gate": sc.ground_truth.expected_human_gate,
                        "injection": sc.ground_truth.expected_injection_detected,
                        "policy_rules": sc.ground_truth.expected_policy_rules,
                    },
                    "predicted": {
                        "risk": r.predicted_risk,
                        "human_gate": r.predicted_human_gate,
                        "injection": r.predicted_injection_detected,
                        "policy_rules": r.predicted_policy_rules,
                    },
                    "mismatches": r.mismatches,
                }
            )

    import sys

    py_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"

    return BenchmarkReport(
        benchmark_version="1.0.0",
        dataset_version="1.0.0",
        execution_timestamp=datetime.now(UTC).isoformat(),
        python_version=py_version,
        prism_version="0.1.0",
        model_mode=model_mode,
        seed=seed,
        total_scenarios=len(active_scenarios),
        metrics=metrics,
        scenario_results=results,
        failure_analysis=failure_analysis,
    )


def run_benchmark_sync(
    scenarios: list[Scenario] | None = None,
    model_mode: str = "mock",
    seed: int = 42,
) -> BenchmarkReport:
    """Synchronous entry point for running the evaluation benchmark."""
    return asyncio.run(run_benchmark(scenarios=scenarios, model_mode=model_mode, seed=seed))
