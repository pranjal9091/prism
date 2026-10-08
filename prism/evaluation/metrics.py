"""Deterministic evaluation metrics engine for PRism benchmark."""

import statistics
from typing import Any

from prism.evaluation.models import (
    BenchmarkMetrics,
    ClassificationMetric,
    ExpectedFinding,
    FindingMatchResult,
    Scenario,
    ScenarioExecutionResult,
)


def match_finding(
    expected: ExpectedFinding,
    predicted_findings: list[dict[str, Any]],
    used_indices: set[int] | None = None,
) -> tuple[bool, dict[str, Any] | None, str, int | None]:
    """Robustly match an expected finding against predicted findings.

    Does not require exact LLM wording. Matches via normalized file path,
    severity, category, approximate line range (within +-15 lines), and title keywords.
    """
    exp_file = expected.file.strip().lower()
    exp_sev = expected.severity.strip().lower()
    exp_cat = expected.category.strip().lower()
    exp_keywords = [k.strip().lower() for k in expected.keywords if k.strip()]

    used = used_indices if used_indices is not None else set()

    for idx, pred in enumerate(predicted_findings):
        if idx in used:
            continue

        pred_file = str(pred.get("file", "")).strip().lower()
        pred_sev = str(pred.get("severity", "")).strip().lower()
        pred_cat = str(pred.get("category", "")).strip().lower()
        pred_title = str(pred.get("title", "")).strip().lower()
        pred_desc = str(pred.get("description", "")).strip().lower()
        pred_line = pred.get("line")

        # 1. File match (exact, suffix, or basename match)
        file_match = (
            exp_file == pred_file
            or pred_file.endswith(exp_file)
            or exp_file.endswith(pred_file)
            or exp_file.split("/")[-1] == pred_file.split("/")[-1]
        )
        if not file_match:
            continue

        # 2. Severity match
        if exp_sev != pred_sev:
            continue

        # 3. Category match (normalized synonyms)
        cat_match = (
            exp_cat == pred_cat
            or (exp_cat in ("test_gap", "testing") and pred_cat in ("test_gap", "testing"))
            or (exp_cat in ("bug", "code_quality") and pred_cat in ("bug", "code_quality"))
            or (exp_cat in ("security", "injection") and pred_cat in ("security", "injection"))
        )
        if not cat_match:
            continue

        # 4. Approximate line match (if line specified in both)
        if expected.approximate_line is not None and pred_line is not None:
            try:
                line_diff = abs(int(pred_line) - expected.approximate_line)
                if line_diff > 15:
                    continue
            except (ValueError, TypeError):
                pass

        # 5. Keyword match (if keywords defined, at least one must appear in title or description)
        if exp_keywords:
            text = f"{pred_title} {pred_desc}"
            if not any(k in text for k in exp_keywords):
                continue

        return True, pred, "Matched on file, severity, category, and keywords", idx

    return False, None, "No matching predicted finding found", None


def evaluate_findings_for_scenario(
    expected_findings: list[ExpectedFinding],
    predicted_findings: list[dict[str, Any]],
) -> tuple[float, float, float, list[FindingMatchResult]]:
    """Calculate precision, recall, and F1 for findings within a single scenario."""
    if not expected_findings and not predicted_findings:
        return 1.0, 1.0, 1.0, []

    if not expected_findings and predicted_findings:
        return 0.0, 1.0, 0.0, []

    if expected_findings and not predicted_findings:
        match_results = [
            FindingMatchResult(expected=ef, matched=False, match_reason="No findings predicted")
            for ef in expected_findings
        ]
        return 1.0, 0.0, 0.0, match_results

    used_indices: set[int] = set()
    match_results = []
    tp = 0

    for ef in expected_findings:
        matched, pred_match, reason, pred_idx = match_finding(ef, predicted_findings, used_indices)
        if matched and pred_idx is not None:
            tp += 1
            used_indices.add(pred_idx)
            match_results.append(
                FindingMatchResult(
                    expected=ef,
                    matched=True,
                    predicted=pred_match,
                    match_reason=reason,
                )
            )
        else:
            match_results.append(
                FindingMatchResult(
                    expected=ef,
                    matched=False,
                    match_reason=reason,
                )
            )

    fp = len(predicted_findings) - tp
    fn = len(expected_findings) - tp

    precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

    return precision, recall, f1, match_results


def calculate_binary_metrics(
    actuals: list[bool],
    predictions: list[bool],
) -> tuple[float, float, float, float]:
    """Compute accuracy, precision, recall, and F1 for a binary indicator."""
    if not actuals:
        return 1.0, 1.0, 1.0, 1.0

    tp = sum(1 for a, p in zip(actuals, predictions) if a and p)
    tn = sum(1 for a, p in zip(actuals, predictions) if not a and not p)
    fp = sum(1 for a, p in zip(actuals, predictions) if not a and p)
    fn = sum(1 for a, p in zip(actuals, predictions) if a and not p)

    total = len(actuals)
    accuracy = (tp + tn) / total if total > 0 else 1.0
    precision = tp / (tp + fp) if (tp + fp) > 0 else (1.0 if (tp + fn) == 0 else 0.0)
    recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

    return accuracy, precision, recall, f1


def calculate_multiclass_metrics(
    actuals: list[str],
    predictions: list[str],
    classes: list[str],
) -> tuple[float, float, dict[str, ClassificationMetric], dict[str, dict[str, int]]]:
    """Compute overall accuracy, macro F1, per-class metrics, and confusion matrix."""
    total = len(actuals)
    if total == 0:
        return 1.0, 1.0, {}, {}

    correct = sum(1 for a, p in zip(actuals, predictions) if a == p)
    accuracy = correct / total

    # Confusion Matrix: cm[actual][predicted] = count
    cm: dict[str, dict[str, int]] = {c: {c_pred: 0 for c_pred in classes} for c in classes}
    for a, p in zip(actuals, predictions):
        if a in cm and p in cm[a]:
            cm[a][p] += 1

    per_class: dict[str, ClassificationMetric] = {}
    f1_scores: list[float] = []

    for c in classes:
        tp = sum(1 for a, p in zip(actuals, predictions) if a == c and p == c)
        fp = sum(1 for a, p in zip(actuals, predictions) if a != c and p == c)
        fn = sum(1 for a, p in zip(actuals, predictions) if a == c and p != c)
        support = sum(1 for a in actuals if a == c)

        prec = tp / (tp + fp) if (tp + fp) > 0 else (1.0 if support == 0 else 0.0)
        rec = tp / (tp + fn) if (tp + fn) > 0 else (1.0 if support == 0 else 0.0)
        f1 = 2 * (prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0

        per_class[c] = ClassificationMetric(
            precision=round(prec, 4),
            recall=round(rec, 4),
            f1=round(f1, 4),
            support=support,
        )
        if support > 0:
            f1_scores.append(f1)

    macro_f1 = statistics.mean(f1_scores) if f1_scores else 1.0

    return accuracy, macro_f1, per_class, cm


def calculate_benchmark_metrics(
    scenarios: list[Scenario],
    results: list[ScenarioExecutionResult],
) -> BenchmarkMetrics:
    """Aggregate individual scenario execution results into complete benchmark metrics."""
    total = len(results)
    if total == 0:
        raise ValueError("Cannot calculate metrics over empty results list.")

    scenario_map = {s.scenario_id: s for s in scenarios}

    # 1. Risk Classification
    risk_classes = ["low", "medium", "high", "critical"]
    actual_risks = [scenario_map[r.scenario_id].ground_truth.expected_risk.lower() for r in results]
    pred_risks = [r.predicted_risk.lower() for r in results]
    risk_acc, risk_macro_f1, risk_per_class, risk_cm = calculate_multiclass_metrics(
        actual_risks, pred_risks, risk_classes
    )

    # 2. HIGH+ Recall (High and Critical count as positive)
    high_actual = [r in ("high", "critical") for r in actual_risks]
    high_pred = [r in ("high", "critical") for r in pred_risks]
    high_tp = sum(1 for a, p in zip(high_actual, high_pred) if a and p)
    high_fn = sum(1 for a, p in zip(high_actual, high_pred) if a and not p)
    high_risk_plus_recall = high_tp / (high_tp + high_fn) if (high_tp + high_fn) > 0 else 1.0

    # 3. Human Gate Metrics
    actual_gates = [scenario_map[r.scenario_id].ground_truth.expected_human_gate for r in results]
    pred_gates = [r.predicted_human_gate for r in results]
    gate_acc, gate_prec, gate_rec, gate_f1 = calculate_binary_metrics(actual_gates, pred_gates)

    # 4. Injection Detection Metrics
    actual_injections = [
        scenario_map[r.scenario_id].ground_truth.expected_injection_detected for r in results
    ]
    pred_injections = [r.predicted_injection_detected for r in results]
    inj_acc, inj_prec, inj_rec, inj_f1 = calculate_binary_metrics(actual_injections, pred_injections)

    # 5. Finding Metrics Across All Scenarios
    total_expected_findings = 0
    total_predicted_findings = 0
    total_matched_findings = 0

    category_findings_data: dict[str, dict[str, int]] = {
        "bug": {"expected": 0, "predicted": 0, "matched": 0},
        "security": {"expected": 0, "predicted": 0, "matched": 0},
        "secret_leak": {"expected": 0, "predicted": 0, "matched": 0},
        "test_gap": {"expected": 0, "predicted": 0, "matched": 0},
        "injection": {"expected": 0, "predicted": 0, "matched": 0},
    }

    for r in results:
        sc = scenario_map[r.scenario_id]
        exp_findings = sc.ground_truth.expected_findings
        pred_findings = r.predicted_findings

        total_expected_findings += len(exp_findings)
        total_predicted_findings += len(pred_findings)

        used_idx: set[int] = set()
        for ef in exp_findings:
            matched, _, _, p_idx = match_finding(ef, pred_findings, used_idx)
            cat_key = ef.category.lower()
            if cat_key in category_findings_data:
                category_findings_data[cat_key]["expected"] += 1

            if matched and p_idx is not None:
                used_idx.add(p_idx)
                total_matched_findings += 1
                if cat_key in category_findings_data:
                    category_findings_data[cat_key]["matched"] += 1

        for pf in pred_findings:
            p_cat = str(pf.get("category", "")).lower()
            if p_cat in category_findings_data:
                category_findings_data[p_cat]["predicted"] += 1

    overall_finding_prec = (
        total_matched_findings / total_predicted_findings if total_predicted_findings > 0 else 1.0
    )
    overall_finding_rec = (
        total_matched_findings / total_expected_findings if total_expected_findings > 0 else 1.0
    )
    overall_finding_f1 = (
        2 * (overall_finding_prec * overall_finding_rec) / (overall_finding_prec + overall_finding_rec)
        if (overall_finding_prec + overall_finding_rec) > 0
        else 0.0
    )

    findings_by_cat: dict[str, dict[str, float]] = {}
    for cat_name, data in category_findings_data.items():
        exp_c = data["expected"]
        pred_c = data["predicted"]
        mat_c = data["matched"]
        p = mat_c / pred_c if pred_c > 0 else (1.0 if exp_c == 0 else 0.0)
        rec = mat_c / exp_c if exp_c > 0 else 1.0
        f1_val = 2 * p * rec / (p + rec) if (p + rec) > 0 else 0.0
        findings_by_cat[cat_name] = {
            "precision": round(p, 4),
            "recall": round(rec, 4),
            "f1": round(f1_val, 4),
            "support": exp_c,
        }

    # 6. Policy Rules Metrics
    policy_rule_matches = 0
    total_exp_rules = sum(len(s.ground_truth.expected_policy_rules) for s in scenarios)
    matched_rule_instances = 0
    predicted_rule_instances = sum(len(r.predicted_policy_rules) for r in results)

    for r in results:
        sc = scenario_map[r.scenario_id]
        expected_set = set(sc.ground_truth.expected_policy_rules)
        predicted_set = set(r.predicted_policy_rules)

        if expected_set.issubset(predicted_set):
            policy_rule_matches += 1

        matched_rule_instances += len(expected_set.intersection(predicted_set))

    policy_acc = policy_rule_matches / total if total > 0 else 1.0
    policy_prec = (
        matched_rule_instances / predicted_rule_instances if predicted_rule_instances > 0 else 1.0
    )
    policy_rec = (
        matched_rule_instances / total_exp_rules if total_exp_rules > 0 else 1.0
    )

    # 7. Latency Metrics
    latencies = [r.execution_duration_ms for r in results]
    lat_mean = statistics.mean(latencies) if latencies else 0.0
    lat_median = statistics.median(latencies) if latencies else 0.0
    lat_min = min(latencies) if latencies else 0.0
    lat_max = max(latencies) if latencies else 0.0
    lat_p95 = (
        statistics.quantiles(latencies, n=20)[18] if len(latencies) >= 20 else lat_max
    )

    # 8. Per-Category Summary
    category_summary: dict[str, dict[str, Any]] = {}
    for cat in ["benign", "code_quality", "security", "critical", "adversarial"]:
        cat_results = [r for r in results if r.category.value == cat]
        cat_count = len(cat_results)
        cat_correct = sum(1 for r in cat_results if r.passed)
        cat_acc = cat_correct / cat_count if cat_count > 0 else 0.0
        category_summary[cat] = {
            "count": cat_count,
            "correct": cat_correct,
            "accuracy": round(cat_acc, 4),
        }

    passed_count = sum(1 for r in results if r.passed)

    return BenchmarkMetrics(
        total_scenarios=total,
        passed_scenarios=passed_count,
        pass_rate=round(passed_count / total, 4),
        risk_accuracy=round(risk_acc, 4),
        risk_macro_f1=round(risk_macro_f1, 4),
        high_risk_plus_recall=round(high_risk_plus_recall, 4),
        risk_per_class=risk_per_class,
        risk_confusion_matrix=risk_cm,
        human_gate_accuracy=round(gate_acc, 4),
        human_gate_precision=round(gate_prec, 4),
        human_gate_recall=round(gate_rec, 4),
        human_gate_f1=round(gate_f1, 4),
        injection_accuracy=round(inj_acc, 4),
        injection_precision=round(inj_prec, 4),
        injection_recall=round(inj_rec, 4),
        injection_f1=round(inj_f1, 4),
        finding_precision=round(overall_finding_prec, 4),
        finding_recall=round(overall_finding_rec, 4),
        finding_f1=round(overall_finding_f1, 4),
        findings_by_category=findings_by_cat,
        policy_rule_accuracy=round(policy_acc, 4),
        policy_rule_precision=round(policy_prec, 4),
        policy_rule_recall=round(policy_rec, 4),
        latency_mean_ms=round(lat_mean, 2),
        latency_median_ms=round(lat_median, 2),
        latency_p95_ms=round(lat_p95, 2),
        latency_min_ms=round(lat_min, 2),
        latency_max_ms=round(lat_max, 2),
        category_summary=category_summary,
    )
