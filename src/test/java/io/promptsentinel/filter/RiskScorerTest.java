package io.promptsentinel.filter;

import io.promptsentinel.types.RiskLevel;
import io.promptsentinel.types.RuleCategory;
import io.promptsentinel.types.RuleMatch;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.within;

class RiskScorerTest {

    private static RuleMatch match(String id, double contribution) {
        return new RuleMatch(id, "Test", RuleCategory.PROMPT_INJECTION, "text", contribution);
    }

    // ── Score computation ─────────────────────────────────────────────────────

    @Test
    void emptyMatchesReturnZero() {
        assertThat(RiskScorer.computeScore(List.of())).isEqualTo(0.0);
    }

    @Test
    void singleMatchEqualsContribution() {
        assertThat(RiskScorer.computeScore(List.of(match("r1", 0.75))))
                .isCloseTo(0.75, within(1e-9));
    }

    @Test
    void twoMatchesHigherThanEitherIndividually() {
        var score = RiskScorer.computeScore(List.of(match("r1", 0.30), match("r2", 0.30)));
        assertThat(score).isGreaterThan(0.30).isLessThan(1.0);
    }

    @Test
    void probabilisticOrFormula() {
        // 1 − (1 − 0.5)(1 − 0.5) = 0.75
        var score = RiskScorer.computeScore(List.of(match("r1", 0.5), match("r2", 0.5)));
        assertThat(score).isCloseTo(0.75, within(1e-9));
    }

    @Test
    void scoreNeverExceedsOne() {
        var manyHighMatches = List.of(
                match("r1", 0.9), match("r2", 0.9), match("r3", 0.9),
                match("r4", 0.9), match("r5", 0.9)
        );
        assertThat(RiskScorer.computeScore(manyHighMatches)).isLessThanOrEqualTo(1.0);
    }

    // ── Risk level thresholds ─────────────────────────────────────────────────

    @ParameterizedTest
    @CsvSource({
        "0.00,  SAFE",
        "0.10,  SAFE",
        "0.149, SAFE",
        "0.15,  LOW",
        "0.25,  LOW",
        "0.349, LOW",
        "0.35,  MEDIUM",
        "0.50,  MEDIUM",
        "0.599, MEDIUM",
        "0.60,  HIGH",
        "0.70,  HIGH",
        "0.799, HIGH",
        "0.80,  CRITICAL",
        "0.95,  CRITICAL",
        "1.00,  CRITICAL"
    })
    void thresholdBoundaries(double score, RiskLevel expected) {
        assertThat(RiskScorer.getRiskLevel(score)).isEqualTo(expected);
    }
}
