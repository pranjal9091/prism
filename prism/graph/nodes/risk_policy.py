"""Risk policy node: Executes deterministic rules engine against PR state."""

import logging
from typing import Any

from prism.graph.state import PRState
from prism.guardrails.policy_engine import DeterministicRiskPolicyEngine

logger = logging.getLogger(__name__)


def create_risk_policy_node():
    """Factory creating the risk policy evaluation node."""

    async def risk_policy_node(state: PRState) -> dict[str, Any]:
        decision = DeterministicRiskPolicyEngine.evaluate(state)
        logger.info(
            "Deterministic Risk Policy evaluated: risk=%s, requires_approval=%s, matched_rules=%s",
            decision.risk_level.value,
            decision.requires_human_approval,
            decision.matched_rules,
        )
        return {
            "risk_decision": decision.model_dump(mode="json"),
            "status": "POLICY_EVALUATED",
        }

    return risk_policy_node
