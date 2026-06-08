package io.promptsentinel.types;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

public enum RuleCategory {
    PROMPT_INJECTION,
    JAILBREAK,
    PII,
    MALICIOUS_CODE,
    DATA_EXFILTRATION,
    SENSITIVE_DISCLOSURE;

    /** Serialised as snake_case in JSON output. */
    @JsonValue
    public String toJson() {
        return name().toLowerCase();
    }

    /** Accepts both "prompt_injection" (JSON/YAML) and "PROMPT_INJECTION" (legacy). */
    @JsonCreator
    public static RuleCategory fromJson(String value) {
        return valueOf(value.toUpperCase());
    }
}
