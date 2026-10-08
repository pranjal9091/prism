"""Tests for benchmark dataset integrity, balance, schema validation, and invariant rules."""

import pytest

from prism.evaluation.dataset import (
    filter_scenarios,
    get_scenario_by_id,
    load_all_scenarios,
    validate_dataset,
)
from prism.evaluation.models import (
    ScenarioCategory,
)


def test_load_all_scenarios_exact_count():
    scenarios = load_all_scenarios()
    assert len(scenarios) == 25


def test_scenario_categories_and_balance():
    scenarios = load_all_scenarios()
    counts = {}
    for s in scenarios:
        cat = s.category.value
        counts[cat] = counts.get(cat, 0) + 1

    expected_categories = {"benign", "code_quality", "security", "critical", "adversarial"}
    assert set(counts.keys()) == expected_categories
    for cat in expected_categories:
        assert counts[cat] == 5, f"Category {cat} must contain exactly 5 scenarios"


def test_unique_scenario_ids():
    scenarios = load_all_scenarios()
    ids = [s.scenario_id for s in scenarios]
    assert len(ids) == len(set(ids)), "Scenario IDs must be strictly unique"


def test_safety_invariants_human_gate_and_injection():
    scenarios = load_all_scenarios()
    for s in scenarios:
        gt = s.ground_truth
        # Invariant 1: High and Critical PRs must require human gate
        if gt.expected_risk in ("high", "critical"):
            assert gt.expected_human_gate is True, (
                f"Scenario {s.scenario_id} is {gt.expected_risk} but expected_human_gate is False"
            )

        # Invariant 2: Adversarial PRs must have injection_detected == True
        if s.category == ScenarioCategory.ADVERSARIAL:
            assert gt.expected_injection_detected is True, (
                f"Adversarial scenario {s.scenario_id} must have expected_injection_detected == True"
            )


def test_get_scenario_by_id_success_and_missing():
    s = get_scenario_by_id("S01")
    assert s.scenario_id == "S01"
    assert s.category == ScenarioCategory.SECURITY

    with pytest.raises(KeyError):
        get_scenario_by_id("NONEXISTENT_99")


def test_filter_scenarios_by_category():
    benign = filter_scenarios(category="benign")
    assert len(benign) == 5
    assert all(s.category == ScenarioCategory.BENIGN for s in benign)

    adversarial = filter_scenarios(category=ScenarioCategory.ADVERSARIAL)
    assert len(adversarial) == 5
    assert all(s.category == ScenarioCategory.ADVERSARIAL for s in adversarial)

    with pytest.raises(ValueError):
        filter_scenarios(category="invalid_category_name")


def test_filter_scenarios_by_id():
    filtered = filter_scenarios(scenario_id="CR01")
    assert len(filtered) == 1
    assert filtered[0].scenario_id == "CR01"


def test_validate_dataset_rejects_wrong_count():
    scenarios = load_all_scenarios()[:20]
    with pytest.raises(ValueError, match="Expected exactly 25 scenarios"):
        validate_dataset(scenarios)


def test_validate_dataset_rejects_duplicate_ids():
    scenarios = load_all_scenarios()
    duplicated = list(scenarios)
    # Overwrite last scenario ID with first
    duplicated[-1] = duplicated[-1].model_copy(update={"scenario_id": duplicated[0].scenario_id})
    with pytest.raises(ValueError, match="Duplicate scenario_id detected"):
        validate_dataset(duplicated)


def test_validate_dataset_rejects_missing_human_gate_on_high():
    scenarios = load_all_scenarios()
    modified = list(scenarios)
    target = next(s for s in modified if s.ground_truth.expected_risk == "high")
    bad_gt = target.ground_truth.model_copy(update={"expected_human_gate": False})
    idx = modified.index(target)
    modified[idx] = target.model_copy(update={"ground_truth": bad_gt})

    with pytest.raises(ValueError, match="Safety invariant violation"):
        validate_dataset(modified)


def test_validate_dataset_rejects_adversarial_without_injection():
    scenarios = load_all_scenarios()
    modified = list(scenarios)
    target = next(s for s in modified if s.category == ScenarioCategory.ADVERSARIAL)
    bad_gt = target.ground_truth.model_copy(update={"expected_injection_detected": False})
    idx = modified.index(target)
    modified[idx] = target.model_copy(update={"ground_truth": bad_gt})

    with pytest.raises(ValueError, match="Dataset invariant violation"):
        validate_dataset(modified)
