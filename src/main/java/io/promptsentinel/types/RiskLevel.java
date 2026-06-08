package io.promptsentinel.types;

import com.fasterxml.jackson.annotation.JsonValue;

public enum RiskLevel {
    SAFE, LOW, MEDIUM, HIGH, CRITICAL;

    @JsonValue
    public String toJson() {
        return name().toLowerCase();
    }
}
