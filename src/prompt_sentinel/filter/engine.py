from prompt_sentinel.filter.rewriter import rewrite
from prompt_sentinel.filter.rules import classify
from prompt_sentinel.filter.scorer import compute_score, get_risk_level
from prompt_sentinel.types import (
    Action,
    FilterResult,
    RiskLevel,
    RuleCategory,
    RuleMatch,
)


class FilterEngine:
    """Orchestrates the full filter pipeline: classify → score → decide → rewrite."""

    def __init__(
        self,
        rewrite_threshold: float = 0.35,
        block_threshold: float = 0.60,
    ) -> None:
        self.rewrite_threshold = rewrite_threshold
        self.block_threshold = block_threshold

    def filter(self, prompt: str) -> FilterResult:
        matches = classify(prompt)
        score = compute_score(matches)
        risk_level = get_risk_level(score)
        action = self._determine_action(score, matches)

        filtered_prompt: str | None
        if action == Action.ALLOW:
            filtered_prompt = prompt
        elif action == Action.REWRITE:
            filtered_prompt = rewrite(prompt, matches)
        else:
            filtered_prompt = None

        return FilterResult(
            allowed=action in (Action.ALLOW, Action.REWRITE),
            action=action,
            risk_level=risk_level,
            risk_score=round(score, 4),
            matches=matches,
            original_prompt=prompt,
            filtered_prompt=filtered_prompt,
            reason=self._build_reason(action, risk_level, matches),
        )

    def _determine_action(self, score: float, matches: list[RuleMatch]) -> Action:
        if score < self.rewrite_threshold:
            return Action.ALLOW
        if score < self.block_threshold:
            pii_only = all(m.category == RuleCategory.PII for m in matches)
            return Action.REWRITE if pii_only else Action.BLOCK
        return Action.BLOCK

    def _build_reason(
        self,
        action: Action,
        risk_level: RiskLevel,
        matches: list[RuleMatch],
    ) -> str | None:
        if action == Action.ALLOW:
            return None
        categories = sorted({m.category.value.replace("_", " ") for m in matches})
        category_str = ", ".join(categories)
        n = len(matches)
        rule_word = "rule" if n == 1 else "rules"
        if action == Action.REWRITE:
            return f"PII detected ({category_str}); sensitive data redacted before forwarding."
        return f"Blocked ({risk_level.value} risk): {n} {rule_word} triggered — {category_str}."
