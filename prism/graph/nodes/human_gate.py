"""Human approval gate node using LangGraph native interrupt()."""

import logging
from typing import Any

from langgraph.types import interrupt

from prism.graph.state import PRState

logger = logging.getLogger(__name__)


def create_human_gate_node():
    """Factory creating the human approval gate node."""

    async def human_gate_node(state: PRState) -> dict[str, Any]:
        risk_decision = state.get("risk_decision", {})
        requires_approval = risk_decision.get("requires_human_approval", False)

        # 1. Low risk PRs pass automatically
        if not requires_approval:
            return {
                "human_approval_status": "AUTO_APPROVED",
                "status": "COMPLETED",
            }

        # 2. Elevated risk PRs pause and wait for explicit human decision
        raw_risk = risk_decision.get("risk_level", "high")
        risk_level_str = raw_risk.value if hasattr(raw_risk, "value") else str(raw_risk)

        interrupt_payload = {
            "repository": state.get("repository"),
            "pull_request_number": state.get("pull_request_number"),
            "risk_level": risk_level_str,
            "reasons": risk_decision.get("reasons", []),
            "matched_rules": risk_decision.get("matched_rules", []),
            "injection_detected": state.get("injection_detection", {}).get("detected", False),
            "total_findings": len(state.get("aggregated_findings", [])),
            "requested_decisions": ["approve", "reject"],
            "prompt": "Elevated risk detected. Explicit human decision ('approve' or 'reject') required.",
        }

        logger.info(
            "Pausing review for PR #%s via LangGraph interrupt(). Awaiting human approval.",
            state.get("pull_request_number"),
        )

        # Triggers LangGraph native interrupt; resumes with provided response
        human_response = interrupt(interrupt_payload)

        # 3. Process human decision (Fail-closed principle)
        if isinstance(human_response, dict):
            decision_raw = str(human_response.get("decision", "")).strip().lower()
            reviewer_notes = human_response.get("notes", "")
        else:
            decision_raw = str(human_response or "").strip().lower()
            reviewer_notes = ""

        if decision_raw in ("approve", "approved"):
            logger.info("Human approval granted for PR #%s", state.get("pull_request_number"))
            return {
                "human_approval_status": "APPROVED",
                "approval_metadata": {
                    "decision": "approve",
                    "notes": reviewer_notes,
                },
                "status": "APPROVED_BY_HUMAN",
            }

        elif decision_raw in ("reject", "rejected"):
            logger.info("Human rejected review for PR #%s", state.get("pull_request_number"))
            return {
                "human_approval_status": "REJECTED",
                "approval_metadata": {
                    "decision": "reject",
                    "notes": reviewer_notes,
                },
                "status": "REJECTED_BY_HUMAN",
            }

        # Fail-closed for any missing, malformed, or unrecognized decision
        error_msg = (
            f"Invalid or missing approval decision '{decision_raw}'. "
            f"Failing closed to prevent unauthorized progression."
        )
        logger.warning(error_msg)
        return {
            "human_approval_status": "REJECTED",
            "approval_metadata": {
                "decision": "invalid",
                "raw_response": str(human_response),
            },
            "errors": [error_msg],
            "status": "REJECTED_INVALID_DECISION",
        }

    return human_gate_node
