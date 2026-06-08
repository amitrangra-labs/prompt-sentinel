package io.promptsentinel.server;

import tools.jackson.databind.ObjectMapper;
import io.modelcontextprotocol.json.McpJsonDefaults;
import io.modelcontextprotocol.server.McpServer;
import io.modelcontextprotocol.server.McpServerFeatures;
import io.modelcontextprotocol.server.transport.StdioServerTransportProvider;
import io.modelcontextprotocol.spec.McpSchema;
import io.promptsentinel.filter.FilterEngine;
import io.promptsentinel.filter.RuleRegistry;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;

/**
 * MCP server entry point.
 *
 * <p>Registers two tools:
 * <ul>
 *   <li>{@code filter_prompt} — runs the full safety-filter pipeline</li>
 *   <li>{@code list_rules}    — lists every active rule for inspection</li>
 * </ul>
 *
 * <p>Claude Desktop config ({@code claude_desktop_config.json}):
 * <pre>{@code
 * {
 *   "mcpServers": {
 *     "prompt-sentinel": {
 *       "command": "java",
 *       "args": ["-jar", "/path/to/prompt-sentinel-0.1.0.jar"]
 *     }
 *   }
 * }
 * }</pre>
 */
public final class PromptSentinelServer {

    /** Jackson mapper for serialising FilterResult to JSON. */
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final FilterEngine ENGINE  = new FilterEngine();

    public static void main(String[] args) throws Exception {
        var transport = new StdioServerTransportProvider(McpJsonDefaults.getMapper());

        var server = McpServer.sync(transport)
                .serverInfo("prompt-sentinel", "0.1.0")
                .capabilities(McpSchema.ServerCapabilities.builder()
                        .tools(Boolean.TRUE)
                        .build())
                .tools(filterPromptTool(), listRulesTool())
                .build();

        // Block main thread until the process receives a shutdown signal.
        // The server processes MCP messages on background threads; when the
        // client closes stdin, the JVM will shut down naturally.
        var shutdownLatch = new CountDownLatch(1);
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            server.closeGracefully();
            shutdownLatch.countDown();
        }));
        shutdownLatch.await();
    }

    // ── Tool schemas ──────────────────────────────────────────────────────────

    private static McpSchema.JsonSchema filterSchema() {
        return new McpSchema.JsonSchema(
                "object",
                Map.of("prompt", Map.of(
                        "type",        "string",
                        "description", "The prompt text to filter"
                )),
                List.of("prompt"),
                null, null, null
        );
    }

    private static McpSchema.JsonSchema emptySchema() {
        return new McpSchema.JsonSchema("object", Map.of(), List.of(), null, null, null);
    }

    // ── Tool definitions ──────────────────────────────────────────────────────

    private static McpServerFeatures.SyncToolSpecification filterPromptTool() {
        var tool = McpSchema.Tool.builder()
                .name("filter_prompt")
                .description("""
                        Filter a prompt through the Prompt Sentinel safety engine.
                        Returns: allowed, action, risk_level, risk_score, matches,
                        original_prompt, filtered_prompt (null when blocked), reason.
                        Use filtered_prompt when allowed is true.
                        When allowed is false, surface the reason instead of answering.
                        """)
                .inputSchema(filterSchema())
                .build();

        return McpServerFeatures.SyncToolSpecification.builder()
                .tool(tool)
                .callHandler((exchange, request) -> {
                    try {
                        var prompt = (String) request.arguments().get("prompt");
                        var result = ENGINE.filter(prompt);
                        var json   = MAPPER.writeValueAsString(result);
                        return McpSchema.CallToolResult.builder()
                                .content(List.of(new McpSchema.TextContent(json)))
                                .isError(false)
                                .build();
                    } catch (Exception e) {
                        return McpSchema.CallToolResult.builder()
                                .content(List.of(new McpSchema.TextContent(
                                        "Error: " + e.getMessage())))
                                .isError(true)
                                .build();
                    }
                })
                .build();
    }

    private static McpServerFeatures.SyncToolSpecification listRulesTool() {
        var tool = McpSchema.Tool.builder()
                .name("list_rules")
                .description("List every active filtering rule with its category and risk contribution.")
                .inputSchema(emptySchema())
                .build();

        return McpServerFeatures.SyncToolSpecification.builder()
                .tool(tool)
                .callHandler((exchange, request) -> {
                    try {
                        var rules = RuleRegistry.rules().stream()
                                .map(r -> Map.of(
                                        "id",                r.id(),
                                        "name",              r.name(),
                                        "category",          r.category().toJson(),
                                        "risk_contribution", r.riskContribution()
                                ))
                                .toList();
                        return McpSchema.CallToolResult.builder()
                                .content(List.of(new McpSchema.TextContent(
                                        MAPPER.writeValueAsString(rules))))
                                .isError(false)
                                .build();
                    } catch (Exception e) {
                        return McpSchema.CallToolResult.builder()
                                .content(List.of(new McpSchema.TextContent(
                                        "Error: " + e.getMessage())))
                                .isError(true)
                                .build();
                    }
                })
                .build();
    }
}
