"""Tests for deterministic evaluation metrics, structural finding matcher, and classification scoring."""


from prism.evaluation.metrics import (
    calculate_benchmark_metrics,
    calculate_binary_metrics,
    calculate_multiclass_metrics,
    evaluate_findings_for_scenario,
    match_finding,
)
from prism.evaluation.models import (
    ExpectedFinding,
    GroundTruth,
    Scenario,
    ScenarioCategory,
    ScenarioExecutionResult,
    ScenarioFile,
)


def test_match_finding_exact_and_suffix():
    expected = ExpectedFinding(
        category="security",
        severity="high",
        title="SQL injection vulnerability",
        file="api/users.py",
        approximate_line=25,
        keywords=["sql", "injection"],
    )

    # 1. Exact match
    pred_exact = {
        "category": "security",
        "severity": "high",
        "title": "Detected SQL injection in query",
        "description": "User input used unsafely",
        "file": "api/users.py",
        "line": 28,
    }
    matched, _, _, idx = match_finding(expected, [pred_exact])
    assert matched is True
    assert idx == 0

    # 2. File suffix match (e.g. full path prefix)
    pred_suffix = {
        "category": "security",
        "severity": "high",
        "title": "SQL Injection found",
        "description": "raw query execution",
        "file": "/repo/sub/api/users.py",
        "line": 26,
    }
    matched, _, _, _ = match_finding(expected, [pred_suffix])
    assert matched is True


def test_match_finding_line_distance_threshold():
    expected = ExpectedFinding(
        category="bug",
        severity="medium",
        title="Null check missing",
        file="utils/parser.py",
        approximate_line=50,
        keywords=["null"],
    )

    # Within 15 lines -> match
    pred_close = {
        "category": "bug",
        "severity": "medium",
        "title": "Possible null dereference",
        "description": "parser fails on null",
        "file": "utils/parser.py",
        "line": 62,  # Diff is 12 <= 15
    }
    matched, _, _, _ = match_finding(expected, [pred_close])
    assert matched is True

    # Far away (>15 lines) -> no match
    pred_far = {
        "category": "bug",
        "severity": "medium",
        "title": "Possible null dereference",
        "description": "parser fails on null",
        "file": "utils/parser.py",
        "line": 90,  # Diff is 40 > 15
    }
    matched, _, _, _ = match_finding(expected, [pred_far])
    assert matched is False


def test_match_finding_category_synonyms():
    expected = ExpectedFinding(
        category="test_gap",
        severity="medium",
        title="Missing tests",
        file="core/calc.py",
        keywords=["test"],
    )
    pred = {
        "category": "testing",  # Synonym category
        "severity": "medium",
        "title": "Add test coverage",
        "description": "missing unit tests",
        "file": "core/calc.py",
    }
    matched, _, _, _ = match_finding(expected, [pred])
    assert matched is True


def test_evaluate_findings_empty_and_partial():
    # Both empty -> perfect score
    p, r, f1, _ = evaluate_findings_for_scenario([], [])
    assert p == 1.0
    assert r == 1.0
    assert f1 == 1.0

    # Expected finding missing -> recall=0
    ef = ExpectedFinding(category="bug", severity="low", title="Typo", file="f.py")
    p, r, f1, _ = evaluate_findings_for_scenario([ef], [])
    assert p == 1.0
    assert r == 0.0
    assert f1 == 0.0

    # Spurious finding predicted -> precision=0
    pred = {"category": "bug", "severity": "low", "title": "Typo", "file": "f.py"}
    p, r, f1, _ = evaluate_findings_for_scenario([], [pred])
    assert p == 0.0
    assert r == 1.0
    assert f1 == 0.0


def test_calculate_binary_metrics_handcrafted():
    actuals = [True, True, False, False]
    predictions = [True, False, False, True]

    # TP=1, FN=1, TN=1, FP=1 -> Acc=2/4=0.5, Prec=1/2=0.5, Rec=1/2=0.5, F1=0.5
    acc, prec, rec, f1 = calculate_binary_metrics(actuals, predictions)
    assert acc == 0.5
    assert prec == 0.5
    assert rec == 0.5
    assert f1 == 0.5


def test_calculate_multiclass_metrics_handcrafted():
    classes = ["low", "medium", "high", "critical"]
    actuals = ["low", "low", "high", "critical"]
    predictions = ["low", "medium", "high", "critical"]

    acc, macro_f1, per_class, cm = calculate_multiclass_metrics(actuals, predictions, classes)

    assert acc == 0.75  # 3 of 4 correct
    assert macro_f1 > 0.5
    assert cm["low"]["low"] == 1
    assert cm["low"]["medium"] == 1
    assert cm["high"]["high"] == 1
    assert cm["critical"]["critical"] == 1
    assert per_class["critical"].f1 == 1.0
    assert per_class["high"].f1 == 1.0


def test_calculate_benchmark_metrics_handcrafted():
    sc1 = Scenario(
        scenario_id="TEST01",
        category=ScenarioCategory.BENIGN,
        title="Benign test",
        repository="org/repo",
        pr_number=1,
        files=[ScenarioFile(filename="readme.md")],
        diff="",
        ground_truth=GroundTruth(
            expected_risk="low",
            expected_human_gate=False,
            expected_injection_detected=False,
        ),
    )
    sc2 = Scenario(
        scenario_id="TEST02",
        category=ScenarioCategory.SECURITY,
        title="Security test",
        repository="org/repo",
        pr_number=2,
        files=[ScenarioFile(filename="auth.py")],
        diff="",
        ground_truth=GroundTruth(
            expected_risk="high",
            expected_human_gate=True,
            expected_injection_detected=False,
            expected_policy_rules=["RULE_AUTH"],
        ),
    )

    r1 = ScenarioExecutionResult(
        scenario_id="TEST01",
        category=ScenarioCategory.BENIGN,
        title="Benign test",
        predicted_risk="low",
        predicted_findings=[],
        predicted_categories=[],
        predicted_policy_rules=[],
        predicted_injection_detected=False,
        predicted_human_gate=False,
        execution_duration_ms=5.0,
        passed=True,
        risk_match=True,
        human_gate_match=True,
        injection_match=True,
        policy_rules_match=True,
        finding_precision=1.0,
        finding_recall=1.0,
        finding_f1=1.0,
    )
    r2 = ScenarioExecutionResult(
        scenario_id="TEST02",
        category=ScenarioCategory.SECURITY,
        title="Security test",
        predicted_risk="high",
        predicted_findings=[],
        predicted_categories=[],
        predicted_policy_rules=["RULE_AUTH"],
        predicted_injection_detected=False,
        predicted_human_gate=True,
        execution_duration_ms=10.0,
        passed=True,
        risk_match=True,
        human_gate_match=True,
        injection_match=True,
        policy_rules_match=True,
        finding_precision=1.0,
        finding_recall=1.0,
        finding_f1=1.0,
    )

    bm = calculate_benchmark_metrics([sc1, sc2], [r1, r2])
    assert bm.total_scenarios == 2
    assert bm.passed_scenarios == 2
    assert bm.risk_accuracy == 1.0
    assert bm.high_risk_plus_recall == 1.0
    assert bm.human_gate_accuracy == 1.0
    assert bm.latency_mean_ms == 7.5
