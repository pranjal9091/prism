#!/usr/bin/env python3
"""PRism Evaluation Benchmark CLI Runner.

Executes seeded pull request scenarios against the PRism LangGraph review pipeline,
computes deterministic safety and quality metrics, and generates evaluation reports.
"""

import argparse
import sys
from pathlib import Path

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from prism.evaluation.dataset import filter_scenarios
from prism.evaluation.report import save_benchmark_artifacts
from prism.evaluation.runner import run_benchmark_sync


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run PRism deterministic evaluation benchmark across seeded PR scenarios.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--category",
        type=str,
        default=None,
        help="Filter scenarios by category (benign, code_quality, security, critical, adversarial).",
    )
    parser.add_argument(
        "--scenario",
        type=str,
        default=None,
        help="Filter to a specific scenario ID (e.g., S01, CR03, B01, A05).",
    )
    parser.add_argument(
        "--model",
        type=str,
        choices=["mock", "live"],
        default="mock",
        help="Model adapter mode: 'mock' for deterministic local evaluation, 'live' for real LLM.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output raw machine-readable JSON to stdout.",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="artifacts/benchmark",
        help="Directory to write latest.json and latest.md benchmark reports.",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for benchmark reproducibility.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    try:
        scenarios = filter_scenarios(category=args.category, scenario_id=args.scenario)
    except (KeyError, ValueError) as exc:
        print(f"Error filtering scenarios: {exc}", file=sys.stderr)
        return 1

    if not scenarios:
        print("No matching scenarios found to execute.", file=sys.stderr)
        return 1

    if not args.json:
        print(f"Executing PRism benchmark ({len(scenarios)} scenarios, model_mode={args.model})...")

    try:
        report = run_benchmark_sync(
            scenarios=scenarios,
            model_mode=args.model,
            seed=args.seed,
        )
    except (RuntimeError, ValueError, KeyError) as exc:
        print(f"Benchmark execution failed: {exc}", file=sys.stderr)
        return 1

    # Save artifacts
    json_path, md_path = save_benchmark_artifacts(report, output_dir=args.output_dir)

    if args.json:
        print(report.model_dump_json(indent=2))
        return 0

    m = report.metrics
    print("\n" + "=" * 60)
    print(" PRism Benchmark Execution Complete")
    print("=" * 60)
    print(f"Total Scenarios:            {report.total_scenarios}")
    print(f"Passed Scenarios:           {m.passed_scenarios} / {m.total_scenarios} ({round(m.pass_rate * 100, 1)}%)")
    print(f"Risk Accuracy:              {round(m.risk_accuracy * 100, 1)}%")
    print(f"Risk Macro F1:              {round(m.risk_macro_f1 * 100, 1)}%")
    print(f"HIGH+ Recall:               {round(m.high_risk_plus_recall * 100, 1)}%")
    print(f"Human Gate Recall:          {round(m.human_gate_recall * 100, 1)}%")
    print(f"Human Gate Accuracy:        {round(m.human_gate_accuracy * 100, 1)}%")
    print(f"Injection Detection Recall: {round(m.injection_recall * 100, 1)}%")
    print(f"Finding F1:                 {round(m.finding_f1 * 100, 1)}%")
    print(f"Policy Accuracy:            {round(m.policy_rule_accuracy * 100, 1)}%")
    print(f"Mean Local Latency:         {m.latency_mean_ms} ms")
    print(f"P95 Local Latency:          {m.latency_p95_ms} ms")
    print("-" * 60)
    print(f"JSON Report:  {json_path}")
    print(f"Markdown:     {md_path}")
    print("=" * 60)

    if report.failure_analysis:
        print(f"\nWARNING: {len(report.failure_analysis)} scenario(s) failed benchmark criteria:")
        for fa in report.failure_analysis:
            print(f"  - [{fa['scenario_id']}] {fa['title']}: {', '.join(fa['mismatches'])}")
        return 1

    print("\nAll benchmark scenarios passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
