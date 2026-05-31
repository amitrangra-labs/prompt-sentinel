"""FastMCP server entry point.

Registers two MCP tools:
  - filter_prompt   main safety-filter tool; returns a full FilterResult
  - list_rules      inspection tool; lists every active rule
"""

from fastmcp import FastMCP

from prompt_sentinel.filter.engine import FilterEngine
from prompt_sentinel.filter.rules import RULES

mcp = FastMCP(
    "prompt-sentinel",
    instructions=(
        "A prompt safety filter. "
        "Call `filter_prompt` before processing any user message. "
        "Use the returned `filtered_prompt` (when `allowed` is true) as the actual input. "
        "When `allowed` is false, surface the `reason` to the user instead of answering."
    ),
)

_engine = FilterEngine()


@mcp.tool()
def filter_prompt(prompt: str) -> dict:  # type: ignore[type-arg]
    """Filter *prompt* through the Prompt Sentinel safety engine.

    Returns a FilterResult payload with:
    - `allowed`          whether the prompt may proceed to the model
    - `action`           "allow" | "rewrite" | "block"
    - `risk_level`       "safe" | "low" | "medium" | "high" | "critical"
    - `risk_score`       aggregated risk in [0.0, 1.0]
    - `matches`          list of triggered rules with matched text
    - `original_prompt`  the prompt as supplied
    - `filtered_prompt`  sanitised prompt (None when blocked)
    - `reason`           human-readable explanation (None when allowed)
    """
    return _engine.filter(prompt).model_dump()


@mcp.tool()
def list_rules() -> list[dict]:  # type: ignore[type-arg]
    """List every active filtering rule with its category and risk weight."""
    return [
        {
            "id": rule.id,
            "name": rule.name,
            "category": rule.category.value,
            "risk_contribution": rule.risk_contribution,
        }
        for rule in RULES
    ]


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
