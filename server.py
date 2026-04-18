# server.py — sift-mcp MCP server entry point
# Registers all IR tools and starts stdio transport

from mcp.server import Server
from mcp.server.stdio import stdio_server

from tools import network, logs, memory, ioc, timeline, case
from constraints import ConstraintError, check_path, require_case
from audit import AuditLogger

audit = AuditLogger()
app = Server("sift-mcp")

# --- Tool registration ---

@app.list_tools()
async def list_tools():
    tools = []
    tools.extend(network.tool_definitions())
    tools.extend(logs.tool_definitions())
    tools.extend(memory.tool_definitions())
    tools.extend(ioc.tool_definitions())
    tools.extend(timeline.tool_definitions())
    tools.extend(case.tool_definitions())
    return tools


@app.call_tool()
async def call_tool(name: str, arguments: dict):
    audit.log_call(name, arguments)
    try:
        if name.startswith("network_"):
            result = await network.dispatch(name, arguments)
        elif name.startswith("logs_"):
            result = await logs.dispatch(name, arguments)
        elif name.startswith("memory_"):
            result = await memory.dispatch(name, arguments)
        elif name.startswith("ioc_"):
            result = await ioc.dispatch(name, arguments)
        elif name.startswith("timeline_"):
            result = await timeline.dispatch(name, arguments)
        elif name.startswith("case_"):
            result = await case.dispatch(name, arguments)
        else:
            raise ValueError(f"Unknown tool: {name}")
        audit.log_result(name, result)
        return result
    except ConstraintError as e:
        audit.log_error(name, str(e))
        raise
    except Exception as e:
        audit.log_error(name, str(e))
        raise


async def main():
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
