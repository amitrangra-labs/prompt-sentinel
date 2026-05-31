import re

from prompt_sentinel.filter.rules import RULES, Rule
from prompt_sentinel.types import RuleCategory, RuleMatch

_PII_PLACEHOLDERS: dict[str, str] = {
    "pii_ssn": "[REDACTED-SSN]",
    "pii_credit_card": "[REDACTED-CC]",
    "pii_email": "[REDACTED-EMAIL]",
    "pii_phone": "[REDACTED-PHONE]",
}

_RULES_BY_ID: dict[str, Rule] = {r.id: r for r in RULES}


def rewrite(prompt: str, matches: list[RuleMatch]) -> str:
    """Redact all PII in *prompt* that was flagged by *matches*.

    Re-runs each PII rule's patterns to catch every occurrence, not just
    the first one stored in the RuleMatch.
    """
    result = prompt
    for match in matches:
        if match.category != RuleCategory.PII:
            continue
        rule = _RULES_BY_ID.get(match.rule_id)
        if rule is None:
            continue
        placeholder = _PII_PLACEHOLDERS.get(match.rule_id, "[REDACTED]")
        for pattern in rule.patterns:
            result = re.sub(pattern, placeholder, result, flags=re.IGNORECASE | re.MULTILINE)
    return result
