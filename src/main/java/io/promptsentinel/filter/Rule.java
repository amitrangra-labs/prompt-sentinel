package io.promptsentinel.filter;

import io.promptsentinel.types.RuleCategory;
import io.promptsentinel.types.RuleMatch;

import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * An immutable rule consisting of one or more compiled regex patterns.
 * {@link #match(String)} returns the first match found, or empty.
 */
public record Rule(
        String       id,
        String       name,
        RuleCategory category,
        List<Pattern> patterns,
        double       riskContribution
) {
    public Optional<RuleMatch> match(String text) {
        for (Pattern p : patterns) {
            var m = p.matcher(text);
            if (m.find()) {
                return Optional.of(new RuleMatch(id, name, category, m.group(), riskContribution));
            }
        }
        return Optional.empty();
    }
}
