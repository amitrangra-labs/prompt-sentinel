import math

from prompt_sentinel.types import RiskLevel, RuleMatch


def compute_score(matches: list[RuleMatch]) -> float:
    """Aggregate individual rule contributions into a single 0.0–1.0 risk score.

    Uses the probabilistic OR formula so that each additional match raises the
    score with diminishing returns rather than a simple sum that could exceed 1.0.

        score = 1 − ∏(1 − contribution_i)
    """
    if not matches:
        return 0.0
    complement = math.prod(1.0 - m.risk_contribution for m in matches)
    return round(min(1.0 - complement, 1.0), 6)


def get_risk_level(score: float) -> RiskLevel:
    if score < 0.15:
        return RiskLevel.SAFE
    if score < 0.35:
        return RiskLevel.LOW
    if score < 0.60:
        return RiskLevel.MEDIUM
    if score < 0.80:
        return RiskLevel.HIGH
    return RiskLevel.CRITICAL
