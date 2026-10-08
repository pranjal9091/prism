"""Report generation utilities for PRism benchmark evaluation."""

from pathlib import Path

from prism.evaluation.models import BenchmarkReport


def generate_markdown_report(report: BenchmarkReport) -> str:
    """Format evaluation benchmark report as human-readable GitHub-flavored Markdown."""
    m = report.metrics

    lines: list[str] = [
        "# PRism Benchmark Report",
        "",
        f"**Benchmark Version:** {report.benchmark_version}  ",
        f"**Dataset Version:** {report.dataset_version}  ",
        f"**Execution Timestamp:** `{report.execution_timestamp}`  ",
        f"**Python Version:** `{report.python_version}`  ",
        f"**Model Mode:** `{report.model_mode}`  ",
        f"**Random Seed:** `{report.seed}`  ",
        "",
        "## Summary Metrics",
        "",
        f"- **Dataset:** {report.total_scenarios} scenarios",
        f"- **Passed Scenarios:** {m.passed_scenarios} / {m.total_scenarios} ({round(m.pass_rate * 100, 1)}%)",
        f"- **Risk Accuracy:** {round(m.risk_accuracy * 100, 1)}%",
        f"- **Risk Macro F1:** {round(m.risk_macro_f1 * 100, 1)}%",
        f"- **HIGH+ Recall:** {round(m.high_risk_plus_recall * 100, 1)}%",
        f"- **Human Gate Recall:** {round(m.human_gate_recall * 100, 1)}%",
        f"- **Human Gate Accuracy:** {round(m.human_gate_accuracy * 100, 1)}%",
        f"- **Injection Detection Recall:** {round(m.injection_recall * 100, 1)}%",
        f"- **Injection Detection Accuracy:** {round(m.injection_accuracy * 100, 1)}%",
        f"- **Finding F1:** {round(m.finding_f1 * 100, 1)}%",
        f"- **Finding Precision:** {round(m.finding_precision * 100, 1)}%",
        f"- **Finding Recall:** {round(m.finding_recall * 100, 1)}%",
        f"- **Policy Accuracy:** {round(m.policy_rule_accuracy * 100, 1)}%",
        f"- **Mean Local Latency:** {m.latency_mean_ms} ms",
        f"- **P95 Local Latency:** {m.latency_p95_ms} ms",
        "",
        "## Risk Confusion Matrix",
        "",
        "| Actual \\ Predicted | Low | Medium | High | Critical |",
        "| :--- | :---: | :---: | :---: | :---: |",
    ]

    for actual_risk in ["low", "medium", "high", "critical"]:
        row = m.risk_confusion_matrix.get(actual_risk, {})
        low_c = row.get("low", 0)
        med_c = row.get("medium", 0)
        high_c = row.get("high", 0)
        crit_c = row.get("critical", 0)
        lines.append(f"| **{actual_risk.upper()}** | {low_c} | {med_c} | {high_c} | {crit_c} |")

    lines.extend([
        "",
        "## Per-category Results",
        "",
        "| Category | Count | Correct | Accuracy |",
        "| :--- | :---: | :---: | :---: |",
    ])

    for cat_name, stats in m.category_summary.items():
        count = stats["count"]
        correct = stats["correct"]
        acc_pct = round(stats["accuracy"] * 100, 1)
        lines.append(f"| **{cat_name.replace('_', ' ').title()}** | {count} | {correct} | {acc_pct}% |")

    lines.extend([
        "",
        "## Finding Metrics By Category",
        "",
        "| Finding Category | Precision | Recall | F1 | Support |",
        "| :--- | :---: | :---: | :---: | :---: |",
    ])

    for f_cat, f_stats in m.findings_by_category.items():
        p_pct = round(f_stats["precision"] * 100, 1)
        r_pct = round(f_stats["recall"] * 100, 1)
        f1_pct = round(f_stats["f1"] * 100, 1)
        supp = f_stats["support"]
        lines.append(f"| **{f_cat}** | {p_pct}% | {r_pct}% | {f1_pct}% | {supp} |")

    lines.extend([
        "",
        "## Execution Latency Profile",
        "",
        "- **Note:** These measurements reflect local deterministic execution duration, not production network latency.",
        f"- **Mean Latency:** {m.latency_mean_ms} ms",
        f"- **Median Latency:** {m.latency_median_ms} ms",
        f"- **P95 Latency:** {m.latency_p95_ms} ms",
        f"- **Min Latency:** {m.latency_min_ms} ms",
        f"- **Max Latency:** {m.latency_max_ms} ms",
        "",
        "## Failure Analysis",
        "",
    ])

    if not report.failure_analysis:
        lines.append("No benchmark mismatches detected.")
    else:
        for fa in report.failure_analysis:
            lines.extend([
                f"### Scenario {fa['scenario_id']} — {fa['title']}",
                "",
                f"- **Expected:** Risk={fa['expected']['risk']}, Gate={fa['expected']['human_gate']}, Injection={fa['expected']['injection']}",
                f"- **Predicted:** Risk={fa['predicted']['risk']}, Gate={fa['predicted']['human_gate']}, Injection={fa['predicted']['injection']}",
                "- **Mismatches:**",
            ])
            for mm in fa["mismatches"]:
                lines.append(f"  - {mm}")
            lines.append("")

    return "\n".join(lines) + "\n"


def save_benchmark_artifacts(
    report: BenchmarkReport,
    output_dir: str | Path | None = None,
) -> tuple[Path, Path]:
    """Save machine-readable JSON and human-readable Markdown benchmark artifacts."""
    out_path = Path(output_dir) if output_dir else Path("artifacts/benchmark")
    out_path.mkdir(parents=True, exist_ok=True)

    json_file = out_path / "latest.json"
    md_file = out_path / "latest.md"

    # Write formatted JSON
    json_content = report.model_dump_json(indent=2)
    json_file.write_text(json_content, encoding="utf-8")

    # Write Markdown
    md_content = generate_markdown_report(report)
    md_file.write_text(md_content, encoding="utf-8")

    return json_file, md_file
