package io.promptsentinel.types;

import com.fasterxml.jackson.annotation.JsonValue;

public enum Action {
    ALLOW, REWRITE, BLOCK;

    @JsonValue
    public String toJson() {
        return name().toLowerCase();
    }
}
