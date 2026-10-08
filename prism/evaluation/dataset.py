"""Dataset loader and strict validation engine for PRism evaluation benchmark."""

from prism.evaluation.models import Scenario, ScenarioCategory
from prism.evaluation.scenarios import ALL_SCENARIOS
from prism.graph.state import FindingCategory, Severity

VALID_RISKS = {s.value for s in Severity}
VALID_CATEGORIES = {c.value for c in ScenarioCategory}
VALID_FINDING_CATEGORIES = {fc.value for fc in FindingCategory}


def load_all_scenarios() -> list[Scenario]:
    """Load and validate all 25 seeded benchmark pull request scenarios."""
    scenarios = list(ALL_SCENARIOS)
    validate_dataset(scenarios)
    return scenarios


def get_scenario_by_id(scenario_id: str) -> Scenario:
    """Retrieve a single scenario by its unique identifier (e.g., 'S01', 'CR03')."""
    normalized_id = scenario_id.strip().upper()
    for scenario in ALL_SCENARIOS:
        if scenario.scenario_id.upper() == normalized_id:
            return scenario
    raise KeyError(f"Scenario '{scenario_id}' not found in benchmark dataset.")


def filter_scenarios(
    category: str | ScenarioCategory | None = None,
    scenario_id: str | None = None,
) -> list[Scenario]:
    """Filter benchmark scenarios by category and/or specific scenario ID."""
    scenarios = load_all_scenarios()

    if scenario_id is not None and scenario_id.strip():
        target_id = scenario_id.strip().upper()
        scenarios = [s for s in scenarios if s.scenario_id.upper() == target_id]
        if not scenarios:
            raise KeyError(f"No scenario found with ID '{scenario_id}'")
        return scenarios

    if category is not None:
        cat_str = category.value if isinstance(category, ScenarioCategory) else str(category).lower().strip()
        scenarios = [s for s in scenarios if s.category.value == cat_str]
        if not scenarios:
            raise ValueError(f"No scenarios found for category '{category}'")

    return scenarios


def validate_dataset(scenarios: list[Scenario]) -> None:
    """Strictly validate dataset integrity, ground-truth schema, and safety invariant rules.

    Raises ValueError with explicit descriptive error on any integrity issue.
    """
    if len(scenarios) != 25:
        raise ValueError(f"Dataset integrity error: Expected exactly 25 scenarios, found {len(scenarios)}")

    seen_ids: set[str] = set()
    category_counts: dict[str, int] = {c.value: 0 for c in ScenarioCategory}

    for idx, s in enumerate(scenarios, 1):
        if not s.scenario_id or not s.scenario_id.strip():
            raise ValueError(f"Scenario #{idx} has missing or empty scenario_id")

        if s.scenario_id in seen_ids:
            raise ValueError(f"Duplicate scenario_id detected: '{s.scenario_id}'")
        seen_ids.add(s.scenario_id)

        cat_val = s.category.value if isinstance(s.category, ScenarioCategory) else str(s.category)
        if cat_val not in category_counts:
            raise ValueError(f"Scenario '{s.scenario_id}' has unrecognized category '{cat_val}'")
        category_counts[cat_val] += 1

        gt = s.ground_truth
        if gt is None:
            raise ValueError(f"Scenario '{s.scenario_id}' has missing ground_truth")

        # Validate expected risk
        risk_val = gt.expected_risk.lower().strip()
        if risk_val not in VALID_RISKS:
            raise ValueError(
                f"Scenario '{s.scenario_id}' has invalid expected_risk '{gt.expected_risk}'. "
                f"Valid choices: {sorted(VALID_RISKS)}"
            )

        # Invariant: Every expected HIGH or CRITICAL risk PR must require human gate
        if risk_val in ("high", "critical") and not gt.expected_human_gate:
            raise ValueError(
                f"Safety invariant violation: Scenario '{s.scenario_id}' has risk '{risk_val}' "
                "but expected_human_gate is False. All HIGH/CRITICAL PRs must require human gate."
            )

        # Invariant: Every adversarial scenario must have expected_injection_detected = True
        if s.category == ScenarioCategory.ADVERSARIAL and not gt.expected_injection_detected:
            raise ValueError(
                f"Dataset invariant violation: Adversarial scenario '{s.scenario_id}' "
                "must have expected_injection_detected = True"
            )

        # Validate expected findings
        for f in gt.expected_findings:
            f_cat = f.category.lower().strip()
            if f_cat not in VALID_FINDING_CATEGORIES:
                raise ValueError(
                    f"Scenario '{s.scenario_id}' finding has invalid category '{f.category}'. "
                    f"Valid choices: {sorted(VALID_FINDING_CATEGORIES)}"
                )
            f_sev = f.severity.lower().strip()
            if f_sev not in VALID_RISKS:
                raise ValueError(
                    f"Scenario '{s.scenario_id}' finding has invalid severity '{f.severity}'. "
                    f"Valid choices: {sorted(VALID_RISKS)}"
                )

    # Invariant: Every category must have exactly 5 scenarios
    for cat_name, count in category_counts.items():
        if count != 5:
            raise ValueError(
                f"Dataset balance violation: Category '{cat_name}' has {count} scenarios; "
                "expected exactly 5."
            )
