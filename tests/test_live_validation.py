"""Unit and regression tests for Milestone 7 live validation harness.

Verifies:
1. Scenario definition validity and expected security risks.
2. Dry-run safety (never publishes to external systems unless explicitly enabled).
3. Failure mode resilience and typed exception mappings.
4. Security firewall capability verification.
5. Rejection path guarantees (zero comments published).
6. That pytest executes deterministically without real API calls.
"""

import pytest

from prism.github.exceptions import (
    GitHubAuthError,
    GitHubNotFoundError,
    GitHubRateLimitError,
    GitHubTimeoutError,
)
from prism.mcp_server.security import Capability, PermissionDeniedError, PermissionFirewall
from scripts.verify_live import (
    LIVE_SCENARIOS,
    RecordingMockGitHubClient,
    create_scenario_mock_llm,
    execute_live_validation,
)


def test_live_scenarios_matrix_completeness():
    """Verify all 5 live scenarios exist with valid categories and risk expectations."""
    assert len(LIVE_SCENARIOS) == 5
    scenario_ids = [s.scenario_id for s in LIVE_SCENARIOS]
    assert scenario_ids == ["LIVE-01", "LIVE-02", "LIVE-03", "LIVE-04", "LIVE-05"]

    # Verify risk mappings
    assert LIVE_SCENARIOS[0].expected_risk == "low"
    assert LIVE_SCENARIOS[0].expected_human_gate is False

    assert LIVE_SCENARIOS[1].expected_risk == "high"
    assert LIVE_SCENARIOS[1].expected_human_gate is True

    assert LIVE_SCENARIOS[2].expected_risk == "critical"
    assert LIVE_SCENARIOS[2].expected_human_gate is True

    assert LIVE_SCENARIOS[3].expected_injection is True
    assert LIVE_SCENARIOS[3].expected_human_gate is True

    assert LIVE_SCENARIOS[4].expected_injection is True
    assert LIVE_SCENARIOS[4].expected_human_gate is True


def test_scenario_mock_llm_findings_generation():
    """Verify create_scenario_mock_llm returns appropriate findings for each scenario."""
    # Benign: zero findings
    benign_llm = create_scenario_mock_llm(LIVE_SCENARIOS[0])
    assert len(benign_llm.security_output.findings) == 0

    # Security: high SQL injection finding
    sec_llm = create_scenario_mock_llm(LIVE_SCENARIOS[1])
    assert len(sec_llm.security_output.findings) == 1
    assert sec_llm.security_output.findings[0].severity.value == "high"

    # Critical secret: critical secret finding
    secret_llm = create_scenario_mock_llm(LIVE_SCENARIOS[2])
    assert len(secret_llm.security_output.findings) == 1
    assert secret_llm.security_output.findings[0].severity.value == "critical"


def test_mcp_security_firewall_capabilities():
    """Verify the firewall permits READ/COMMENT and strictly denies dangerous capabilities."""
    firewall = PermissionFirewall()

    # Allowed operations
    assert firewall.validate_operation("get_pr") == Capability.READ
    assert firewall.validate_operation("post_review_comment") == Capability.COMMENT

    # Blocked operations
    for dangerous in ["merge", "push", "write_file", "delete_file", "create_branch", "admin", "run_bash"]:
        with pytest.raises(PermissionDeniedError):
            firewall.validate_operation(dangerous)


def test_typed_github_exceptions():
    """Verify typed GitHub exceptions are distinct and capture status codes."""
    auth_err = GitHubAuthError("Auth error", status_code=401)
    assert auth_err.status_code == 401

    rate_err = GitHubRateLimitError("Rate limit error", status_code=429)
    assert rate_err.status_code == 429

    not_found = GitHubNotFoundError("Not found", status_code=404)
    assert not_found.status_code == 404

    timeout_err = GitHubTimeoutError("Timed out")
    assert "Timed out" in str(timeout_err)


@pytest.mark.asyncio
async def test_recording_mock_github_client():
    """Verify RecordingMockGitHubClient records calls and enforces safety."""
    client = RecordingMockGitHubClient()
    meta = await client.get_pr_metadata("org", "repo", 42)
    assert meta.number == 42

    result = await client.post_review_comment("org", "repo", 42, "Summary comment")
    assert result.id == 9000
    assert len(client.published_comments) == 1

    inline_result = await client.post_review_comment(
        "org", "repo", 42, "Inline comment", commit_id="sha1", path="app.py", line=10
    )
    assert inline_result.id == 7000
    assert len(client.published_inline_comments) == 1


@pytest.mark.asyncio
async def test_live_validation_runner_dry_run_execution():
    """Verify the live validation harness executes cleanly in dry-run mode."""
    # Run only benign and security scenarios to keep test fast
    results = await execute_live_validation(
        dry_run=True,
        publish_live=False,
        scenario_filter="LIVE-01",
        target_repo="prism-org/prism-live-test",
    )

    assert results["summary"]["total_scenarios"] == 1
    assert results["summary"]["passed_scenarios"] == 1
    assert results["summary"]["rejection_path_verified"] is True
    assert results["summary"]["duplicate_prevention_verified"] is True
    assert results["summary"]["webhook_verified"] is True
    assert results["summary"]["security_firewall_verified"] is True
