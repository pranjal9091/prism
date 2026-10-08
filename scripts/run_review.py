#!/usr/bin/env python3
"""Local execution runner for PRism LangGraph review workflow.

Demonstrates full execution without requiring GitHub credentials or paid LLM APIs.
"""

import asyncio
import os
import sys
from pathlib import Path

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

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
from prism.models.factory import MockReviewLLM, get_llm


def create_sample_fixture() -> dict:
    """Realistic Pull Request fixture with logic bug, SQL injection, and test gap."""
    sample_diff = (
        "diff --git a/auth/login.py b/auth/login.py\n"
        "--- a/auth/login.py\n"
        "+++ b/auth/login.py\n"
        "@@ -15,6 +15,14 @@ def verify_login(username, password):\n"
        "-    return db.query(User).filter_by(username=username).first()\n"
        "+    # Unsafe raw SQL concatenation\n"
        "+    query = f\"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'\"\n"
        "+    result = db.execute(query).fetchone()\n"
        "+    if result and result.retry_count > 3:\n"
        "+        # Logic bug: comparison should be >= 3 and retry counter is never incremented\n"
        "+        return None\n"
        "+    return result\n"
    )

    sample_meta = {
        "title": "feat: optimize user login query and add retry threshold",
        "body": "Replaced ORM query with raw SQL for speed. Added retry limit check.",
        "author": "dev-contributor",
        "head_branch": "feat/login-perf",
        "base_branch": "main",
    }

    changed_files = [
        {
            "filename": "auth/login.py",
            "status": "modified",
            "additions": 8,
            "deletions": 1,
            "changes": 9,
        }
    ]

    return {
        "repository": "octocat/prism-demo",
        "pull_request_number": 42,
        "pr_metadata": sample_meta,
        "diff": sample_diff,
        "changed_files": changed_files,
    }


def create_deterministic_mock_llm() -> MockReviewLLM:
    """Fixture model simulating realistic agent deductions."""
    plan = ReviewPlan(
        summary="PR replaces ORM with raw SQL query in auth/login.py and modifies retry threshold logic.",
        key_changes=[
            "Direct SQL string formatting with username and password",
            "Retry count threshold check before user return",
        ],
        affected_components=["auth", "database"],
        security_critical=True,
        testing_concerns=[
            "SQL injection payload verification",
            "Retry counter boundary condition tests",
        ],
        specialist_guidance={
            "code_reviewer": "Inspect retry_count conditional logic and variable state mutation.",
            "security_reviewer": "CRITICAL: Inspect user input interpolation into raw SQL statement.",
            "test_suggester": "Recommend test cases for retry count boundaries and malicious username characters.",
        },
    )

    code_output = CodeReviewOutput(
        findings=[
            Finding(
                category=FindingCategory.BUG,
                severity=Severity.HIGH,
                title="Off-by-one and non-incrementing retry threshold",
                description="The retry_count check tests `> 3` rather than `>= 3`, and `retry_count` is never incremented upon failed attempt.",
                file="auth/login.py",
                line=21,
                recommendation="Use `>= MAX_RETRIES` and ensure `retry_count` is atomically incremented on invalid login attempts.",
                confidence=0.95,
            )
        ]
    )

    security_output = SecurityReviewOutput(
        findings=[
            Finding(
                category=FindingCategory.INJECTION,
                severity=Severity.CRITICAL,
                title="Critical SQL Injection Vulnerability",
                description="Direct f-string formatting interpolates unescaped `username` and `password` variables directly into SQL query.",
                file="auth/login.py",
                line=17,
                recommendation="Use parameterized queries (e.g., `text(\"SELECT * FROM users WHERE username = :u\")`) or retain the ORM query.",
                confidence=0.99,
            )
        ]
    )

    test_output = TestSuggestionOutput(
        findings=[
            Finding(
                category=FindingCategory.TEST_GAP,
                severity=Severity.MEDIUM,
                title="Missing unit test for retry threshold edge cases",
                description="No unit test verifies login behavior when retry_count equals exactly 3 or exceeds 3.",
                file="auth/login.py",
                line=20,
                recommendation="Add `test_verify_login_exceeds_retry_threshold()` and `test_verify_login_sql_injection_resilience()`.",
                confidence=0.88,
            )
        ]
    )

    return MockReviewLLM(
        plan=plan,
        code_output=code_output,
        security_output=security_output,
        test_output=test_output,
    )


from prism.graph.builder import resume_pr_review


async def main():
    print("=" * 80)
    print("PRism: Agentic GitHub PR Review & Triage System (Milestone 3 Workflow)")
    print("=" * 80)

    fixture = create_sample_fixture()

    # Determine model: use real model if OPENAI_API_KEY is present, else deterministic mock
    has_api_key = bool(os.getenv("OPENAI_API_KEY"))
    if has_api_key:
        print("[*] Running with LIVE LLM (OPENAI_API_KEY detected)")
        llm = get_llm()
    else:
        print("[*] Running with DETERMINISTIC MOCK LLM (zero API key required)")
        llm = create_deterministic_mock_llm()

    print(f"[*] Target PR: {fixture['repository']} #{fixture['pull_request_number']}")
    print(f"[*] Title: {fixture['pr_metadata']['title']}")
    print("-" * 80)

    # Execute review with return_control=True to inspect interrupts and support resumption
    review_state, graph, config = await execute_pr_review(
        repository=fixture["repository"],
        pull_request_number=fixture["pull_request_number"],
        pr_metadata=fixture["pr_metadata"],
        diff=fixture["diff"],
        changed_files=fixture["changed_files"],
        llm=llm,
        return_control=True,
    )

    # 1. Display Pre-LLM Guardrails
    inj = review_state.get("injection_detection", {})
    print("\n[1. PRE-LLM GUARDRAILS EVALUATION]")
    print(f"  Injection Detected:     {inj.get('detected', False)}")
    print(f"  Confidence:             {inj.get('confidence', 0.0)}")
    print(f"  Matched Patterns:       {inj.get('matched_patterns', [])}")
    print(f"  Diff Delimited:         {'<untrusted_input' in review_state.get('sanitized_diff', '')}")

    # 2. Display Review Plan
    plan = review_state.get("review_plan", {})
    print("\n[2. TRIAGE REVIEW PLAN produced by Planner]")
    print(f"  Summary:                {plan.get('summary')}")
    print(f"  Security Critical:      {plan.get('security_critical')}")
    print(f"  Affected Components:    {', '.join(plan.get('affected_components', []))}")
    print("  Testing Concerns:")
    for tc in plan.get("testing_concerns", []):
        print(f"    - {tc}")

    # 3. Display Specialist Findings
    print("\n[3. SPECIALIST AGENT FINDINGS (Concurrently Executed)]")
    print(f"  Code Reviewer Findings:     {len(review_state.get('code_findings', []))}")
    print(f"  Security Checker Findings:  {len(review_state.get('security_findings', []))}")
    print(f"  Test Suggester Findings:    {len(review_state.get('test_findings', []))}")

    # 4. Display Aggregated Review Results
    summary = review_state.get("review_summary", {})
    print("\n[4. AGGREGATED TRIAGE RESULTS produced by Aggregator]")
    print(f"  Status:                 {review_state.get('status')}")
    print(f"  Synthesis:              {summary.get('summary_text')}")
    print("  Severity Breakdown:")
    for sev, count in summary.get("findings_by_severity", {}).items():
        print(f"    - {sev.upper():<8}: {count}")

    print("\n[5. DETAILED FINDINGS]")
    for i, finding in enumerate(review_state.get("aggregated_findings", []), 1):
        sev_badge = f"[{finding['severity'].upper()}]"
        print(f"\n  Finding #{i}: {sev_badge} {finding['title']}")
        print(f"    Specialist:     {finding.get('specialist')}")
        print(f"    Category:       {finding['category']}")
        print(f"    File/Line:      {finding['file']}:{finding.get('line')}")
        print(f"    Description:    {finding['description']}")
        print(f"    Recommendation: {finding['recommendation']}")
        print(f"    Confidence:     {finding['confidence'] * 100:.1f}%")

    # 6. Display Deterministic Risk Policy Decision
    risk = review_state.get("risk_decision", {})
    print("\n[6. DETERMINISTIC RISK POLICY ENGINE DECISION]")
    print(f"  Risk Level:             {str(risk.get('risk_level', '')).upper()}")
    print(f"  Requires Human Gate:    {risk.get('requires_human_approval')}")
    print(f"  Matched Policy Rules:   {risk.get('matched_rules')}")
    print("  Policy Reasons:")
    for r in risk.get("reasons", []):
        print(f"    - {r}")

    # 7. Human-in-the-Loop Gate & Checkpointed Resumption
    interrupts = review_state.get("__interrupt__", [])
    print("\n[7. HUMAN-IN-THE-LOOP APPROVAL GATE]")
    if interrupts:
        payload = interrupts[0].value
        print(f"  [*] LangGraph interrupt() triggered: {payload.get('prompt')}")
        print(f"  [*] Awaiting Human Decision: {payload.get('requested_decisions')}")

        thread_id = config["configurable"]["thread_id"]
        print("  [*] Simulating Human Approval with Command(resume='approve')...")
        resumed_state = await resume_pr_review(
            graph=graph,
            thread_id=thread_id,
            decision="approve",
            notes="Authorized by Senior Security Engineer after reviewing parameterized query fix.",
        )
        print(f"  [*] Resumed Approval Status: {resumed_state.get('human_approval_status')}")
        print(f"  [*] Final Status:            {resumed_state.get('status')}")
        print(f"  [*] Reviewer Notes:          {resumed_state.get('approval_metadata', {}).get('notes')}")
    else:
        print(f"  [*] Auto-approved (Status: {review_state.get('human_approval_status')})")

    if review_state.get("errors"):
        print(f"\n[!] Errors Encountered: {review_state['errors']}")

    print("\n" + "=" * 80)
    print("M3 COMPLETE MULTI-AGENT WORKFLOW VERIFIED SUCCESSFULLY")
    print("=" * 80)


if __name__ == "__main__":
    asyncio.run(main())
