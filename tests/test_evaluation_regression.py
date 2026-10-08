"""Regression tests for benchmark reporting, artifact generation, and security boundaries."""

import json
import tempfile
from pathlib import Path

import pytest

from prism.evaluation.dataset import load_all_scenarios
from prism.evaluation.report import generate_markdown_report, save_benchmark_artifacts
from prism.evaluation.runner import run_benchmark_sync
from prism.mcp_server.security import PermissionDeniedError, PermissionFirewall


def test_benchmark_report_schema_and_markdown_sections():
    scenarios = load_all_scenarios()[:3]
    report = run_benchmark_sync(scenarios=scenarios, model_mode="mock")

    assert report.benchmark_version == "1.0.0"
    assert report.dataset_version == "1.0.0"
    assert report.prism_version == "0.1.0"
    assert report.python_version != ""
    assert report.execution_timestamp != ""
    assert report.total_scenarios == 3
    assert len(report.scenario_results) == 3

    md = generate_markdown_report(report)
    assert "# PRism Benchmark Report" in md
    assert "## Summary Metrics" in md
    assert "## Risk Confusion Matrix" in md
    assert "## Per-category Results" in md
    assert "## Failure Analysis" in md


def test_save_benchmark_artifacts_to_disk():
    scenarios = load_all_scenarios()[:2]
    report = run_benchmark_sync(scenarios=scenarios, model_mode="mock")

    with tempfile.TemporaryDirectory() as tmpdir:
        json_path, md_path = save_benchmark_artifacts(report, output_dir=tmpdir)

        assert json_path.exists()
        assert md_path.exists()

        # Validate JSON content
        data = json.loads(json_path.read_text(encoding="utf-8"))
        assert data["total_scenarios"] == 2
        assert "metrics" in data
        assert "risk_accuracy" in data["metrics"]

        # Validate Markdown content
        md_text = md_path.read_text(encoding="utf-8")
        assert "Risk Accuracy" in md_text


def test_benchmark_scenarios_cannot_bypass_security_firewall():
    denied_tools = [
        "merge_pull_request",
        "delete_branch",
        "push_commit",
        "create_release",
        "modify_repository_secrets",
    ]

    for tool_name in denied_tools:
        with pytest.raises(PermissionDeniedError):
            PermissionFirewall.validate_operation(tool_name)


def test_benchmark_artifacts_do_not_leak_live_api_keys():
    artifacts_dir = Path("artifacts/benchmark")
    if artifacts_dir.exists():
        for file in artifacts_dir.glob("latest.*"):
            content = file.read_text(encoding="utf-8")
            assert "sk-proj-" not in content
            assert "OPENAI_API_KEY=" not in content
