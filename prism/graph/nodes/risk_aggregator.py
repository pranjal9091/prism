"""Aggregator node: Merges, deduplicates, and synthesizes findings from parallel specialists."""

import logging
from typing import Any

from pydantic import ValidationError

from prism.graph.state import Finding, PRState, Severity

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {
    Severity.CRITICAL.value: 4,
    Severity.HIGH.value: 3,
    Severity.MEDIUM.value: 2,
    Severity.LOW.value: 1,
}


def deduplicate_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Deduplicate findings based on file, line, and normalized title.

    If duplicates appear from different specialists, retains the finding with the
    higher severity and records contributing specialists.
    """
    seen: dict[tuple[str, int | None, str], dict[str, Any]] = {}

    for f in findings:
        file_key = f.get("file", "").strip().lower()
        line_key = f.get("line")
        title_key = f.get("title", "").strip().lower()
        key = (file_key, line_key, title_key)

        if key in seen:
            existing = seen[key]
            existing_sev = existing.get("severity", "low")
            new_sev = f.get("severity", "low")

            # Upgrade severity if the new finding is higher severity
            if SEVERITY_ORDER.get(new_sev, 1) > SEVERITY_ORDER.get(existing_sev, 1):
                existing["severity"] = new_sev
                existing["description"] = f.get("description", existing["description"])
                existing["recommendation"] = f.get("recommendation", existing["recommendation"])

            # Combine specialist citations
            current_spec = existing.get("specialist", "")
            new_spec = f.get("specialist", "")
            if new_spec and new_spec not in current_spec:
                existing["specialist"] = f"{current_spec}, {new_spec}" if current_spec else new_spec
        else:
            seen[key] = dict(f)

    return list(seen.values())


def create_aggregator_node():
    """Factory creating the risk aggregator node."""

    async def aggregator_node(state: PRState) -> dict[str, Any]:
        code_findings = state.get("code_findings", [])
        sec_findings = state.get("security_findings", [])
        test_findings = state.get("test_findings", [])

        all_raw = list(code_findings) + list(sec_findings) + list(test_findings)
        deduped = deduplicate_findings(all_raw)

        # Validate findings against Finding schema to guarantee integrity
        validated_findings: list[dict[str, Any]] = []
        validation_errors: list[str] = []

        for item in deduped:
            try:
                finding_obj = Finding.model_validate(item)
                validated_findings.append(finding_obj.model_dump(mode="json"))
            except (ValidationError, ValueError, TypeError) as exc:
                validation_errors.append(f"Invalid finding discarded ({item.get('title')}): {exc}")

        # Tally severities
        severity_counts = {
            Severity.CRITICAL.value: 0,
            Severity.HIGH.value: 0,
            Severity.MEDIUM.value: 0,
            Severity.LOW.value: 0,
        }
        for f in validated_findings:
            sev = f.get("severity", "low").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1
            else:
                severity_counts[Severity.LOW.value] += 1

        total = len(validated_findings)
        summary_text = (
            f"Review complete: {total} total findings identified "
            f"({severity_counts['critical']} critical, {severity_counts['high']} high, "
            f"{severity_counts['medium']} medium, {severity_counts['low']} low)."
        )

        review_summary = {
            "summary_text": summary_text,
            "total_findings": total,
            "findings_by_severity": severity_counts,
            "contributing_specialists": {
                "code_reviewer_count": len(code_findings),
                "security_reviewer_count": len(sec_findings),
                "test_suggester_count": len(test_findings),
            },
        }

        updates: dict[str, Any] = {
            "aggregated_findings": validated_findings,
            "review_summary": review_summary,
            "status": "AGGREGATED",
        }
        if validation_errors:
            updates["errors"] = validation_errors

        return updates

    return aggregator_node
