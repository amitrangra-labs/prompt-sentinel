package io.promptsentinel.filter;

import io.promptsentinel.types.RuleMatch;

import java.util.List;

/**
 * Runs a prompt through every registered rule and returns the list of matches.
 * Each rule contributes at most one {@link RuleMatch} (first pattern hit wins).
 */
public final class RuleClassifier {

    private RuleClassifier() {}

    public static List<RuleMatch> classify(String text) {
        return RuleRegistry.rules().stream()
                           .flatMap(rule -> rule.match(text).stream())
                           .toList();
    }
}
