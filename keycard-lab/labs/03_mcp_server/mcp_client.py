"""Call the protected MCP server as a user (labs 03, 04).

  python labs/03_mcp_server/mcp_client.py --user alice                 # list tools + whoami
  python labs/03_mcp_server/mcp_client.py --user alice --tool recent_commits
  python labs/03_mcp_server/mcp_client.py --user alice --tool open_incident_issue --arg title="db down"
  python labs/03_mcp_server/mcp_client.py --url http://localhost:8100/mcp --user bob ...   (via gateway, lab 10)

The client first signs the user in (PKCE, audience = the MCP server), then
sends every MCP request with Authorization: Bearer <token>.
"""
import argparse
import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import httpx2  # the MCP SDK uses httpx2, not httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from common import settings
from common.login import load_or_login


async def run(url: str, token: str, tool: str | None, args: dict) -> None:
    async with httpx2.AsyncClient(headers={"Authorization": f"Bearer {token}"}, timeout=30) as http:
        async with streamable_http_client(url, http_client=http) as streams:
            async with ClientSession(streams[0], streams[1]) as s:
                await s.initialize()
                tools = await s.list_tools()
                print("tools visible:", [t.name for t in tools.tools])
                try:
                    result = await s.call_tool(tool or "whoami", args)
                except Exception as e:  # e.g. gateway policy denial (JSON-RPC -32603)
                    print(f"DENIED: {e}")
                    return
                for part in result.content:
                    text = getattr(part, "text", part)
                    try:
                        print(json.dumps(json.loads(text), indent=2))
                    except (TypeError, ValueError):
                        print(text)
                if result.is_error:
                    print("(tool returned an error)")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default=settings.MCP_RESOURCE, help="MCP endpoint = its Resource identifier")
    ap.add_argument("--user", help="mock zone: alice | bob | carol")
    ap.add_argument("--tool")
    ap.add_argument("--arg", action="append", default=[], help="key=value")
    ap.add_argument("--fresh", action="store_true", help="sign in again")
    a = ap.parse_args()
    token = load_or_login(a.url, a.user, fresh=a.fresh)
    asyncio.run(run(a.url, token, a.tool, dict(kv.split("=", 1) for kv in a.arg)))


if __name__ == "__main__":
    main()
