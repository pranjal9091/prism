"""Unit tests for the Risk Aggregator node."""

import pytest

from prism.graph.nodes.risk_aggregator import create_aggregator_node
from prism.graph.state import FindingCategory, PRState, Severity


@pytest.mark.asyncio
async def test_aggregator_merges_and_deduplicates():
    code_finding = {
        "category": FindingCategory.BUG.value,
        "severity": Severity.MEDIUM.value,
        "title": "SQL Injection Risk",
        "description": "User input passed to execute.",
        "file": "db.py",
        "line": 15,
        "recommendation": "Use query parameters.",
        "confidence": 0.8,
        "specialist": "code_reviewer",
    }

    # Security specialist catches the same line with CRITICAL severity
    security_finding = {
        "category": FindingCategory.INJECTION.value,
        "severity": Severity.CRITICAL.value,
        "title": "SQL Injection Risk",
        "description": "Direct string formatting in SQL query causes critical injection vulnerability.",
        "file": "db.py",
        "line": 15,
        "recommendation": "Use parameterized prepared statements.",
        "confidence": 0.99,
        "specialist": "security_reviewer",
    }

    test_finding = {
        "category": FindingCategory.TEST_GAP.value,
        "severity": Severity.LOW.value,
        "title": "Missing unit test for db query helper",
        "description": "Helper function lacks direct unit tests.",
        "file": "db.py",
        "line": 30,
        "recommendation": "Add test_query_helper.",
        "confidence": 0.75,
        "specialist": "test_suggester",
    }

    state: PRState = {
        "code_findings": [code_finding],
        "security_findings": [security_finding],
        "test_findings": [test_finding],
    }

    aggregator = create_aggregator_node()
    result = await aggregator(state)

    assert result["status"] == "AGGREGATED"
    aggregated = result["aggregated_findings"]
    # 3 raw findings became 2 after deduplicating line 15
    assert len(aggregated) == 2

    # Verify line 15 finding upgraded to CRITICAL and has both specialists listed
    sql_finding = next(f for f in aggregated if f["line"] == 15)
    assert sql_finding["severity"] == Severity.CRITICAL.value
    assert "code_reviewer" in sql_finding["specialist"]
    assert "security_reviewer" in sql_finding["specialist"]

    # Verify severity summary counts
    summary = result["review_summary"]
    assert summary["total_findings"] == 2
    assert summary["findings_by_severity"]["critical"] == 1
    assert summary["findings_by_severity"]["low"] == 1


@pytest.mark.asyncio
async def test_aggregator_empty_findings():
    state: PRState = {
        "code_findings": [],
        "security_findings": [],
        "test_findings": [],
    }

    aggregator = create_aggregator_node()
    result = await aggregator(state)

    assert result["status"] == "AGGREGATED"
    assert result["aggregated_findings"] == []
    assert result["review_summary"]["total_findings"] == 0
    assert result["review_summary"]["findings_by_severity"]["critical"] == 0


@pytest.mark.asyncio
async def test_aggregator_discards_invalid_findings_gracefully():
    # Malformed finding missing mandatory 'file'
    bad_finding = {
        "category": FindingCategory.BUG.value,
        "severity": Severity.LOW.value,
        "title": "Bad Finding",
        "description": "Missing file field",
        "recommendation": "Fix it",
        "confidence": 0.5,
    }

    state: PRState = {
        "code_findings": [bad_finding],
        "security_findings": [],
        "test_findings": [],
    }

    aggregator = create_aggregator_node()
    result = await aggregator(state)

    assert result["aggregated_findings"] == []
    assert "errors" in result
    assert len(result["errors"]) == 1
    assert "Invalid finding discarded" in result["errors"][0]
