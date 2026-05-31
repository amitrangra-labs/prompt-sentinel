import re
from dataclasses import dataclass

from prompt_sentinel.types import RuleCategory, RuleMatch


@dataclass
class Rule:
    id: str
    name: str
    category: RuleCategory
    patterns: list[str]
    risk_contribution: float  # 0.0–1.0

    def match(self, text: str) -> RuleMatch | None:
        """Return the first match found in *text*, or None."""
        for pattern in self.patterns:
            m = re.search(pattern, text, re.IGNORECASE | re.MULTILINE | re.DOTALL)
            if m:
                return RuleMatch(
                    rule_id=self.id,
                    rule_name=self.name,
                    category=self.category,
                    matched_text=m.group(0),
                    risk_contribution=self.risk_contribution,
                )
        return None


RULES: list[Rule] = [
    # ── Prompt Injection ──────────────────────────────────────────────────────
    Rule(
        id="pi_ignore_instructions",
        name="Ignore Previous Instructions",
        category=RuleCategory.PROMPT_INJECTION,
        patterns=[
            r"ignore\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+instructions",
            r"disregard\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+(?:instructions|guidelines|rules)",
        ],
        risk_contribution=0.75,
    ),
    Rule(
        id="pi_override_system",
        name="System Prompt Override",
        category=RuleCategory.PROMPT_INJECTION,
        patterns=[
            r"(?:override|replace|reset)\s+(?:your\s+)?(?:system\s+prompt|system\s+instructions|previous\s+instructions)",
            r"new\s+system\s+prompt\s*:",
            r"your\s+(?:new|updated|real|actual)\s+instructions?\s*(?:are|is)\s*:",
        ],
        risk_contribution=0.80,
    ),
    Rule(
        id="pi_forget_context",
        name="Context Erasure Injection",
        category=RuleCategory.PROMPT_INJECTION,
        patterns=[
            r"forget\s+(?:everything|all)\s+(?:i(?:'ve|\s+have)\s+(?:said|told\s+you)|(?:prior|previous|above)\s+(?:instructions|context))",
            r"(?:clear|erase|delete)\s+(?:your\s+)?(?:memory|context|instructions|system\s+prompt)",
        ],
        risk_contribution=0.70,
    ),
    Rule(
        id="pi_token_smuggling",
        name="Token Smuggling / Delimiter Abuse",
        category=RuleCategory.PROMPT_INJECTION,
        patterns=[
            r"<\|(?:im_start|im_end|endoftext|system|user|assistant)\|>",
            r"\[INST\].*\[/INST\]",
            r"#{3,}\s*(?:SYSTEM|INSTRUCTIONS?|PROMPT)\s*#{3,}",
        ],
        risk_contribution=0.80,
    ),
    # ── Jailbreak ─────────────────────────────────────────────────────────────
    Rule(
        id="jb_dan",
        name="DAN / Do Anything Now",
        category=RuleCategory.JAILBREAK,
        patterns=[
            r"\bDAN\b",
            r"do\s+anything\s+now",
            r"jailbreak(?:ed)?\s+(?:mode|version|ai|prompt)",
        ],
        risk_contribution=0.85,
    ),
    Rule(
        id="jb_unrestricted_ai",
        name="Unrestricted AI Persona",
        category=RuleCategory.JAILBREAK,
        patterns=[
            r"(?:act|pretend|behave)\s+(?:as\s+(?:if\s+)?(?:you\s+(?:are|have)\s+)?|like\s+)(?:an?\s+)?(?:AI|model|assistant|chatbot)\s+(?:with(?:out)\s+(?:any\s+)?(?:restrictions?|limitations?|filters?|guidelines?|ethical\s+(?:constraints?|guidelines?)|safety(?:\s+measures?)?)|that\s+(?:has\s+)?no\s+(?:restrictions?|limitations?|filters?))",
            r"you\s+(?:have|had)\s+no\s+(?:restrictions?|limitations?|ethical\s+(?:constraints?|guidelines?)|safety(?:\s+(?:measures?|guidelines?))?)",
            r"(?:enable|activate|switch\s+to)\s+(?:developer|god|unrestricted|jailbreak|evil|chaos)\s+mode",
            r"(?:you\s+are\s+)?(?:now\s+)?(?:an?\s+)?(?:unrestricted|uncensored|unfiltered)\s+(?:AI|version|mode|model)",
        ],
        risk_contribution=0.85,
    ),
    Rule(
        id="jb_roleplay_bypass",
        name="Roleplay Safety Bypass",
        category=RuleCategory.JAILBREAK,
        patterns=[
            r"(?:in\s+this\s+)?(?:roleplay|story|fictional|hypothetical)\s+(?:scenario|context|setting|universe|world).*(?:no\s+(?:restrictions?|rules?|limits?|guidelines?)|anything\s+(?:goes|is\s+allowed))",
            r"(?:pretend|imagine)\s+(?:you\s+are|you're|this\s+is)\s+a\s+(?:story|game|simulation)\s+where.*(?:allowed?|permitted?|no\s+rules?)",
            r"grandma\s+(?:used\s+to\s+)?(?:tell|read|explain).*(?:steps?|how\s+to|instructions?)",
        ],
        risk_contribution=0.80,
    ),
    # ── PII ───────────────────────────────────────────────────────────────────
    Rule(
        id="pii_ssn",
        name="Social Security Number",
        category=RuleCategory.PII,
        patterns=[r"\b\d{3}-\d{2}-\d{4}\b"],
        risk_contribution=0.55,
    ),
    Rule(
        id="pii_credit_card",
        name="Credit Card Number",
        category=RuleCategory.PII,
        patterns=[r"\b(?:\d{4}[\s\-]){3}\d{4}\b"],
        risk_contribution=0.65,
    ),
    Rule(
        id="pii_email",
        name="Email Address",
        category=RuleCategory.PII,
        patterns=[r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"],
        risk_contribution=0.30,
    ),
    Rule(
        id="pii_phone",
        name="Phone Number",
        category=RuleCategory.PII,
        patterns=[r"\b(?:\+?1[\s.\-]?)?\(?\d{3}\)?[\s.\-]\d{3}[\s.\-]\d{4}\b"],
        risk_contribution=0.30,
    ),
    # ── Malicious Code ────────────────────────────────────────────────────────
    Rule(
        id="code_shell_destroy",
        name="Destructive Shell Command",
        category=RuleCategory.MALICIOUS_CODE,
        patterns=[
            r"rm\s+-[rf]{1,2}\s+(?:[/~]|\S*/\S*)",
            r":\(\)\s*\{\s*:\|:&\s*\}\s*;:",  # fork bomb
            r"mkfs\.\w+\s+/dev/",
            r"dd\s+if=.*of=/dev/(?:sd[a-z]|hd[a-z]|nvme\d)",
        ],
        risk_contribution=0.90,
    ),
    Rule(
        id="code_exec_eval",
        name="Dynamic Code Execution",
        category=RuleCategory.MALICIOUS_CODE,
        patterns=[
            r"\beval\s*\(",
            r"\bexec\s*\(",
            r"__import__\s*\(",
            r"compile\s*\([^)]*exec",
            r"getattr\s*\(__builtins__",
        ],
        risk_contribution=0.65,
    ),
    Rule(
        id="code_os_execution",
        name="OS Command Execution",
        category=RuleCategory.MALICIOUS_CODE,
        patterns=[
            r"\bos\.system\s*\(",
            r"\bsubprocess\.(?:run|call|Popen|check_output|check_call)\s*\(",
            r"\bos\.popen\s*\(",
        ],
        risk_contribution=0.65,
    ),
    Rule(
        id="code_pipe_shell",
        name="Download and Execute",
        category=RuleCategory.MALICIOUS_CODE,
        patterns=[
            r"(?:curl|wget)\s+\S+\s*\|\s*(?:ba)?sh\b",
            r"(?:curl|wget)\s+\S+\s*\|\s*(?:python3?|perl|ruby)\b",
        ],
        risk_contribution=0.85,
    ),
    # ── Data Exfiltration ─────────────────────────────────────────────────────
    Rule(
        id="exfil_send_data",
        name="Data Exfiltration Request",
        category=RuleCategory.DATA_EXFILTRATION,
        patterns=[
            r"(?:send|transmit|upload|post|exfiltrate)\s+(?:(?:all|the|this|my|our)\s+)+(?:data|information|content|results?|secrets?|credentials?|tokens?)\s+to\b",
            r"(?:leak|steal|exfiltrate|extract)\s+(?:all\s+)?(?:the\s+)?(?:data|information|credentials?|secrets?|api\s+keys?|passwords?)\b",
        ],
        risk_contribution=0.80,
    ),
    Rule(
        id="exfil_webhook",
        name="Suspicious Exfiltration Endpoint",
        category=RuleCategory.DATA_EXFILTRATION,
        patterns=[
            r"(?:webhook\.site|requestbin|pipedream\.net|burpcollaborator|canarytokens|interactsh)",
            r"(?:ngrok|localtunnel)\.(?:io|com|app)/\S+",
        ],
        risk_contribution=0.75,
    ),
    # ── Sensitive Disclosure ──────────────────────────────────────────────────
    Rule(
        id="sd_system_prompt",
        name="System Prompt Extraction",
        category=RuleCategory.SENSITIVE_DISCLOSURE,
        patterns=[
            r"(?:what\s+is|show(?:\s+me)?|reveal|print|repeat|output|display|tell\s+me)\s+(?:your|the)\s+(?:full\s+|complete\s+|exact\s+)?system\s+prompt",
            r"(?:what\s+(?:are|were)|show(?:\s+me)?|reveal|print|output)\s+(?:your|the)\s+(?:full\s+|complete\s+|exact\s+)?(?:instructions?|guidelines?|rules?|constraints?)",
            r"print\s+(?:everything|all\s+text)\s+(?:above|before)\s+(?:this|my\s+message|the\s+user)",
        ],
        risk_contribution=0.60,
    ),
    Rule(
        id="sd_training_data",
        name="Training Data Extraction",
        category=RuleCategory.SENSITIVE_DISCLOSURE,
        patterns=[
            r"(?:repeat|output|show|print|extract)\s+(?:your\s+)?training\s+data",
            r"(?:what\s+(?:data|text|content)\s+(?:were|was)\s+you\s+trained\s+on|tell\s+me\s+(?:your\s+)?training\s+(?:data|corpus))",
        ],
        risk_contribution=0.50,
    ),
]


def classify(text: str) -> list[RuleMatch]:
    """Run *text* through all rules and return every rule that fires."""
    matches: list[RuleMatch] = []
    for rule in RULES:
        m = rule.match(text)
        if m is not None:
            matches.append(m)
    return matches
