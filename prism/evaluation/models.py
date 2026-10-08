"""Data models and schemas for PRism evaluation harness and benchmark dataset."""

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class ScenarioCategory(str, Enum):
    """Scenario category partition."""

    BENIGN = "benign"
    CODE_QUALITY = "code_quality"
    SECURITY = "security"
    CRITICAL = "critical"
    ADVERSARIAL = "adversarial"


class ExpectedFinding(BaseModel):
    """Ground-truth expected finding specification."""

    category: str
    severity: str
    title: str
    file: str
    approximate_line: int | None = None
    keywords: list[str] = Field(default_factory=list)


class GroundTruth(BaseModel):
    """Explicit ground-truth expectations for a benchmark scenario."""

    expected_risk: str
    expected_findings: list[ExpectedFinding] = Field(default_factory=list)
    expected_categories: list[str] = Field(default_factory=list)
    expected_policy_rules: list[str] = Field(default_factory=list)
    expected_human_gate: bool
    expected_injection_detected: bool


class ScenarioFile(BaseModel):
    """Simulated pull request changed file representation."""

    filename: str
    status: str = "modified"
    patch: str | None = None


class Scenario(BaseModel):
    """Complete benchmark pull request scenario specification."""

    scenario_id: str
    category: ScenarioCategory
    title: str
    repository: str
    pr_number: int
    base_sha: str = "000000000000"
    head_sha: str = "111111111111"
    files: list[ScenarioFile]
    diff: str
    body: str = ""
    author: str = "contributor"
    ground_truth: GroundTruth


class FindingMatchResult(BaseModel):
    """Result of matching a predicted finding to ground truth."""

    expected: ExpectedFinding
    matched: bool
    predicted: dict[str, Any] | None = None
    match_reason: str = ""


class ScenarioExecutionResult(BaseModel):
    """Execution telemetry and metric comparison for a single scenario."""

    scenario_id: str
    category: ScenarioCategory
    title: str
    predicted_risk: str
    predicted_findings: list[dict[str, Any]] = Field(default_factory=list)
    predicted_categories: list[str] = Field(default_factory=list)
    predicted_policy_rules: list[str] = Field(default_factory=list)
    predicted_injection_detected: bool
    predicted_human_gate: bool
    execution_duration_ms: float
    passed: bool
    risk_match: bool
    human_gate_match: bool
    injection_match: bool
    policy_rules_match: bool
    finding_precision: float
    finding_recall: float
    finding_f1: float
    mismatches: list[str] = Field(default_factory=list)


class ClassificationMetric(BaseModel):
    """Precision, recall, and F1 for a specific class."""

    precision: float
    recall: float
    f1: float
    support: int


class BenchmarkMetrics(BaseModel):
    """Aggregated evaluation metrics across benchmark execution."""

    total_scenarios: int
    passed_scenarios: int
    pass_rate: float

    # Risk metrics
    risk_accuracy: float
    risk_macro_f1: float
    high_risk_plus_recall: float
    risk_per_class: dict[str, ClassificationMetric]
    risk_confusion_matrix: dict[str, dict[str, int]]

    # Human Gate metrics
    human_gate_accuracy: float
    human_gate_precision: float
    human_gate_recall: float
    human_gate_f1: float

    # Injection metrics
    injection_accuracy: float
    injection_precision: float
    injection_recall: float
    injection_f1: float

    # Finding metrics
    finding_precision: float
    finding_recall: float
    finding_f1: float
    findings_by_category: dict[str, dict[str, float]]

    # Policy rule metrics
    policy_rule_accuracy: float
    policy_rule_precision: float
    policy_rule_recall: float

    # Local benchmark latency (milliseconds)
    latency_mean_ms: float
    latency_median_ms: float
    latency_p95_ms: float
    latency_min_ms: float
    latency_max_ms: float

    # Per-category summary
    category_summary: dict[str, dict[str, Any]]


class BenchmarkReport(BaseModel):
    """Complete machine-readable benchmark report."""

    benchmark_version: str = "1.0.0"
    dataset_version: str = "1.0.0"
    execution_timestamp: str
    python_version: str
    prism_version: str = "0.1.0"
    model_mode: str = "mock"
    seed: int | None = 42
    total_scenarios: int
    metrics: BenchmarkMetrics
    scenario_results: list[ScenarioExecutionResult]
    failure_analysis: list[dict[str, Any]] = Field(default_factory=list)
