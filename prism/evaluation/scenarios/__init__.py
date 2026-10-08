"""PRism 25-scenario evaluation dataset registry."""

from prism.evaluation.scenarios.adversarial import ADVERSARIAL_SCENARIOS
from prism.evaluation.scenarios.benign import BENIGN_SCENARIOS
from prism.evaluation.scenarios.code_quality import CODE_QUALITY_SCENARIOS
from prism.evaluation.scenarios.critical import CRITICAL_SCENARIOS
from prism.evaluation.scenarios.security import SECURITY_SCENARIOS

ALL_SCENARIOS = [
    *BENIGN_SCENARIOS,
    *CODE_QUALITY_SCENARIOS,
    *SECURITY_SCENARIOS,
    *CRITICAL_SCENARIOS,
    *ADVERSARIAL_SCENARIOS,
]

__all__ = [
    "ADVERSARIAL_SCENARIOS",
    "ALL_SCENARIOS",
    "BENIGN_SCENARIOS",
    "CODE_QUALITY_SCENARIOS",
    "CRITICAL_SCENARIOS",
    "SECURITY_SCENARIOS",
]
