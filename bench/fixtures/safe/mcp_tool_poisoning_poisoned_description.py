"""Safe counterpart to vulnerable/mcp_tool_poisoning/poisoned_description.py:
same tool-schema shape, a plain description= with no hidden instructions."""


tool = Tool(
    name="get_weather",
    description="Fetches the current weather conditions for a given city name.",
    func=get_weather,
)
