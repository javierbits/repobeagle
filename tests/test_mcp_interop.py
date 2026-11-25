#!/usr/bin/env python3
"""Interop test with the official MCP Python SDK (a real client, not the synthetic stdio test).

Skips with a note when the SDK is absent, so the suite still runs on a bare python3.
"""
import asyncio, json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import repobeagle as rb

try:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
except ImportError:
    print("SKIP mcp interop: MCP SDK not installed (pip install -r requirements-dev.txt)")
    sys.exit(0)

fail = 0
def check(name, ok):
    global fail
    print(("PASS " if ok else "FAIL ") + name)
    if not ok:
        fail = 1

async def interop():
    params = StdioServerParameters(command=sys.executable, args=[str(ROOT / "repobeagle.py"), "mcp"])
    report = None
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            init = await session.initialize()
            check("SDK initialize: server identity and version",
                  init.server_info.name == "repobeagle" and init.server_info.version == rb.VERSION)
            check("SDK initialize: protocol negotiated", bool(init.protocol_version))
            check("SDK ping round-trip", (await session.send_ping()) is not None)
            tools = {t.name: t for t in (await session.list_tools()).tools}
            check("SDK lists exactly the documented tools",
                  sorted(tools) == ["explain_report", "scan_repo", "verify_badge"])
            check("wire schemas match the declared MCP_TOOLS contract",
                  all(tools[t["name"]].input_schema == t["inputSchema"] for t in rb.MCP_TOOLS))
            res = await session.call_tool("scan_repo", {"target": str(ROOT / "tests/fixtures/trap-npm"),
                                                       "network": False, "timeout_seconds": 120})
            payload = json.loads(res.content[0].text) if not res.is_error and res.content else {}
            check("SDK scan_repo returns the fixture verdict",
                  payload.get("verdict") == "RED" and (payload.get("counts") or {}).get("critical", 0) >= 2
                  and payload.get("findings_total", 0) >= 3)
            report = payload.get("report")
            explained = await session.call_tool("explain_report", {"report": report or ""})
            ep = json.loads(explained.content[0].text) if not explained.is_error and explained.content else {}
            check("SDK explain_report consumes the scan output",
                  ep.get("exit_code") == 0 and "thresholds:" in ep.get("explanation", ""))
            invalid = await session.call_tool("scan_repo", {})
            check("SDK invalid arguments surface as isError",
                  invalid.is_error and "target is required" in invalid.content[0].text)
            tiny = await session.call_tool("scan_repo", {"target": str(ROOT / "tests/fixtures/trap-npm"),
                                                         "network": False, "timeout_seconds": 1})
            check("SDK rejects timeout_seconds outside 5..1800",
                  tiny.is_error and "timeout_seconds" in tiny.content[0].text)
            unknown = await session.call_tool("nope", {})
            check("SDK unknown tool surfaces as isError", unknown.is_error)
    check("SDK scan report was kept on disk", report is not None and Path(report).is_file())

asyncio.run(interop())
sys.exit(fail)
