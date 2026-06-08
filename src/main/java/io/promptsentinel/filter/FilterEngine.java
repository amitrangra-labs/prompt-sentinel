package io.promptsentinel.filter;

import io.promptsentinel.types.*;

import java.util.List;
import java.util.stream.Collectors;

/**
 * Orchestrates the full filter pipeline:
 * classify → score → decide (allow / rewrite / block) → rewrite if needed.
 *
 * <p>Thresholds are configurable; defaults match the published risk table:
 * <ul>
 *   <li>score &lt; {@code rewriteThreshold} → ALLOW</li>
 *   <li>score &lt; {@code blockThreshold}   → REWRITE (PII-only) or BLOCK</li>
 *   <li>score ≥ {@code blockThreshold}      → BLOCK</li>
 * </ul>
 */
public final class FilterEngine {

    private final double rewriteThreshold;
    private final double blockThreshold;

    /** Default thresholds: rewrite at 0.35, block at 0.60. */
    public FilterEngine() {
        this(0.35, 0.60);
    }

    public FilterEngine(double rewriteThreshold, double blockThreshold) {
        this.rewriteThreshold = rewriteThreshold;
        this.blockThreshold   = blockThreshold;
    }

    public FilterResult filter(String prompt) {
        var matches   = RuleClassifier.classify(prompt);
        double score  = RiskScorer.computeScore(matches);
        var riskLevel = RiskScorer.getRiskLevel(score);
        var action    = determineAction(score, matches);

        String filteredPrompt = switch (action) {
            case ALLOW   -> prompt;
            case REWRITE -> PromptRewriter.rewrite(prompt, matches);
            case BLOCK   -> null;
        };

        return new FilterResult(
                action != Action.BLOCK,
                action,
                riskLevel,
                Math.round(score * 10_000.0) / 10_000.0,
                matches,
                prompt,
                filteredPrompt,
                buildReason(action, riskLevel, matches)
        );
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    private Action determineAction(double score, List<RuleMatch> matches) {
        if (score < rewriteThreshold) return Action.ALLOW;
        if (score < blockThreshold) {
            boolean piiOnly = matches.stream()
                                     .allMatch(m -> m.category() == RuleCategory.PII);
            return piiOnly ? Action.REWRITE : Action.BLOCK;
        }
        return Action.BLOCK;
    }

    private static String buildReason(Action action, RiskLevel riskLevel, List<RuleMatch> matches) {
        if (action == Action.ALLOW) return null;

        var categories = matches.stream()
                .map(m -> m.category().toJson().replace('_', ' '))
                .distinct()
                .sorted()
                .collect(Collectors.joining(", "));

        int n = matches.size();
        String ruleWord = n == 1 ? "rule" : "rules";

        return switch (action) {
            case REWRITE -> "PII detected (%s); sensitive data redacted before forwarding.".formatted(categories);
            case BLOCK   -> "Blocked (%s risk): %d %s triggered — %s.".formatted(
                                riskLevel.toJson(), n, ruleWord, categories);
            default      -> null;
        };
    }
}
