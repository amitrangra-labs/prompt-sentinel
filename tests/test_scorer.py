import pytest

from prompt_sentinel.filter.scorer import compute_score, get_risk_level
from prompt_sentinel.types import RiskLevel, RuleCategory, RuleMatch


def _match(rule_id: str, contribution: float) -> RuleMatch:
    return RuleMatch(
        rule_id=rule_id,
        rule_name="Test Rule",
        category=RuleCategory.PROMPT_INJECTION,
        matched_text="test match",
        risk_contribution=contribution,
    )


class TestComputeScore:
    def test_empty_returns_zero(self) -> None:
        assert compute_score([]) == 0.0

    def test_single_match_equals_contribution(self) -> None:
        assert compute_score([_match("r1", 0.75)]) == pytest.approx(0.75)

    def test_two_matches_higher_than_max_individual(self) -> None:
        matches = [_match("r1", 0.30), _match("r2", 0.30)]
        score = compute_score(matches)
        assert score > 0.30
        assert score < 1.0

    def test_probabilistic_or_formula(self) -> None:
        # 1 − (1 − 0.5)(1 − 0.5) = 1 − 0.25 = 0.75
        matches = [_match("r1", 0.5), _match("r2", 0.5)]
        assert compute_score(matches) == pytest.approx(0.75)

    def test_score_never_exceeds_one(self) -> None:
        matches = [_match(f"r{i}", 0.9) for i in range(10)]
        assert compute_score(matches) <= 1.0

    def test_high_single_contribution(self) -> None:
        assert compute_score([_match("r1", 0.85)]) == pytest.approx(0.85)


class TestGetRiskLevel:
    @pytest.mark.parametrize(
        ("score", "expected"),
        [
            (0.0, RiskLevel.SAFE),
            (0.10, RiskLevel.SAFE),
            (0.149, RiskLevel.SAFE),
            (0.15, RiskLevel.LOW),
            (0.25, RiskLevel.LOW),
            (0.349, RiskLevel.LOW),
            (0.35, RiskLevel.MEDIUM),
            (0.50, RiskLevel.MEDIUM),
            (0.599, RiskLevel.MEDIUM),
            (0.60, RiskLevel.HIGH),
            (0.70, RiskLevel.HIGH),
            (0.799, RiskLevel.HIGH),
            (0.80, RiskLevel.CRITICAL),
            (0.95, RiskLevel.CRITICAL),
            (1.0, RiskLevel.CRITICAL),
        ],
    )
    def test_threshold_boundaries(self, score: float, expected: RiskLevel) -> None:
        assert get_risk_level(score) == expected
