package io.promptsentinel.types;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * A single rule that fired against a prompt, together with the matched text
 * and that rule's contribution to the overall risk score.
 */
public record RuleMatch(
        @JsonProperty("rule_id")          String       ruleId,
        @JsonProperty("rule_name")        String       ruleName,
                                          RuleCategory category,
        @JsonProperty("matched_text")     String       matchedText,
        @JsonProperty("risk_contribution") double      riskContribution
) {}
