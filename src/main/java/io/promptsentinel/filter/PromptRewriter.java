package io.promptsentinel.filter;

import io.promptsentinel.types.RuleCategory;
import io.promptsentinel.types.RuleMatch;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Redacts PII from a prompt by re-running each fired PII rule's patterns
 * across the full text, replacing every occurrence with a safe placeholder.
 */
public final class PromptRewriter {

    private static final Map<String, String> PLACEHOLDERS = Map.of(
            "pii_ssn",         "[REDACTED-SSN]",
            "pii_credit_card", "[REDACTED-CC]",
            "pii_email",       "[REDACTED-EMAIL]",
            "pii_phone",       "[REDACTED-PHONE]"
    );

    private PromptRewriter() {}

    public static String rewrite(String prompt, List<RuleMatch> matches) {
        Set<String> piiRuleIds = matches.stream()
                .filter(m -> m.category() == RuleCategory.PII)
                .map(RuleMatch::ruleId)
                .collect(Collectors.toSet());

        if (piiRuleIds.isEmpty()) return prompt;

        var result = prompt;
        for (Rule rule : RuleRegistry.rules()) {
            if (!piiRuleIds.contains(rule.id())) continue;
            var placeholder = PLACEHOLDERS.getOrDefault(rule.id(), "[REDACTED]");
            for (var pattern : rule.patterns()) {
                result = pattern.matcher(result).replaceAll(placeholder);
            }
        }
        return result;
    }
}
