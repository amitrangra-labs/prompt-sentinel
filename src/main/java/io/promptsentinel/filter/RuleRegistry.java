package io.promptsentinel.filter;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import io.promptsentinel.types.RuleCategory;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Loads and caches the rule list from {@code /rules.yaml} on the classpath.
 *
 * <p>Rules are loaded once at class initialisation. To hot-reload rules at
 * runtime (Phase B), replace the static initialiser with a scheduled refresh
 * backed by a database or file-watcher.
 */
public final class RuleRegistry {

    private static final List<Rule> RULES = load();

    private RuleRegistry() {}

    public static List<Rule> rules() {
        return RULES;
    }

    // ── Loading ───────────────────────────────────────────────────────────────

    private static List<Rule> load() {
        var mapper = new ObjectMapper(new YAMLFactory());
        mapper.findAndRegisterModules();

        try (InputStream in = RuleRegistry.class.getResourceAsStream("/rules.yaml")) {
            if (in == null) {
                throw new IllegalStateException("rules.yaml not found on classpath");
            }
            return mapper.readValue(in, RulesFile.class)
                         .rules()
                         .stream()
                         .map(RuleRegistry::compile)
                         .toList();
        } catch (IOException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    private static Rule compile(RuleDefinition d) {
        var flags = Pattern.CASE_INSENSITIVE | Pattern.DOTALL | Pattern.MULTILINE;
        var compiled = d.patterns().stream()
                        .map(p -> Pattern.compile(p, flags))
                        .toList();
        return new Rule(d.id(), d.name(), d.category(), compiled, d.riskContribution());
    }

    // ── Jackson DTOs ──────────────────────────────────────────────────────────

    record RulesFile(List<RuleDefinition> rules) {}

    record RuleDefinition(
            String       id,
            String       name,
            RuleCategory category,
            @JsonProperty("riskContribution") double riskContribution,
            List<String> patterns
    ) {}
}
