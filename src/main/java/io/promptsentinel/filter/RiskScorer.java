package io.promptsentinel.filter;

import io.promptsentinel.types.RiskLevel;
import io.promptsentinel.types.RuleMatch;

import java.util.List;

/**
 * Aggregates individual rule contributions into a single 0.0–1.0 risk score
 * using the <em>probabilistic OR</em> formula:
 *
 * <pre>score = 1 − ∏(1 − cᵢ)</pre>
 *
 * <p>Multiple weak signals compound with diminishing returns, and the result
 * is naturally capped at 1.0 without special-casing.
 */
public final class RiskScorer {

    private RiskScorer() {}

    public static double computeScore(List<RuleMatch> matches) {
        if (matches.isEmpty()) return 0.0;
        double complement = matches.stream()
                                   .mapToDouble(m -> 1.0 - m.riskContribution())
                                   .reduce(1.0, (a, b) -> a * b);
        return Math.min(1.0 - complement, 1.0);
    }

    public static RiskLevel getRiskLevel(double score) {
        if (score < 0.15) return RiskLevel.SAFE;
        if (score < 0.35) return RiskLevel.LOW;
        if (score < 0.60) return RiskLevel.MEDIUM;
        if (score < 0.80) return RiskLevel.HIGH;
        return RiskLevel.CRITICAL;
    }
}
