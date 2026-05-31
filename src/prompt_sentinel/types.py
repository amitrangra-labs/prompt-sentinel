from enum import StrEnum

from pydantic import BaseModel, Field


class RiskLevel(StrEnum):
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Action(StrEnum):
    ALLOW = "allow"
    REWRITE = "rewrite"
    BLOCK = "block"


class RuleCategory(StrEnum):
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    PII = "pii"
    MALICIOUS_CODE = "malicious_code"
    DATA_EXFILTRATION = "data_exfiltration"
    SENSITIVE_DISCLOSURE = "sensitive_disclosure"


class RuleMatch(BaseModel):
    rule_id: str
    rule_name: str
    category: RuleCategory
    matched_text: str
    risk_contribution: float = Field(ge=0.0, le=1.0)


class FilterResult(BaseModel):
    allowed: bool
    action: Action
    risk_level: RiskLevel
    risk_score: float = Field(ge=0.0, le=1.0)
    matches: list[RuleMatch] = Field(default_factory=list)
    original_prompt: str
    filtered_prompt: str | None
    reason: str | None = None
