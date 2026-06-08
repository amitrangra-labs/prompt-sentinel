package io.promptsentinel.types;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/**
 * The complete output of the filter pipeline for a single prompt.
 *
 * <ul>
 *   <li>{@code allowed}         — whether the prompt may proceed to the model</li>
 *   <li>{@code action}          — allow | rewrite | block</li>
 *   <li>{@code riskLevel}       — safe | low | medium | high | critical</li>
 *   <li>{@code riskScore}       — aggregated score in [0.0, 1.0]</li>
 *   <li>{@code matches}         — every rule that fired</li>
 *   <li>{@code originalPrompt}  — prompt as supplied</li>
 *   <li>{@code filteredPrompt}  — sanitised prompt, or {@code null} when blocked</li>
 *   <li>{@code reason}          — human-readable explanation, or {@code null} when allowed</li>
 * </ul>
 */
public record FilterResult(
                                            boolean      allowed,
                                            Action       action,
        @JsonProperty("risk_level")         RiskLevel    riskLevel,
        @JsonProperty("risk_score")         double       riskScore,
                                            List<RuleMatch> matches,
        @JsonProperty("original_prompt")    String       originalPrompt,
        @JsonProperty("filtered_prompt")    String       filteredPrompt,
                                            String       reason
) {}
