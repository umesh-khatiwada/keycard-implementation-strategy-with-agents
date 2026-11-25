# Lab 10: gateway (allow one tool, deny the next)

**Proves:** per-tool rules can be enforced outside the agent code, with `action = Keycard::Action::"mcp::tools/call::<tool>"` checked for the user and the gateway app. Denied tools are left out of `tools/list`, and denied calls never reach the server (JSON-RPC `-32603` over HTTP 403). Policy changes apply on the next call.

`mini_gateway.py` (port 8100) is a **mock-only stand-in** for Keycard's hosted Unified Access Gateway.

```bash
GW="--url http://localhost:8100/mcp"
.venv/bin/python labs/03_mcp_server/mcp_client.py $GW --user bob   --tool open_incident_issue --arg title="db down"
.venv/bin/python labs/03_mcp_server/mcp_client.py $GW --user alice --tool open_incident_issue --arg title="db down"
./mz policy enable 91_freeze-issue-creation        # kill switch
.venv/bin/python labs/03_mcp_server/mcp_client.py $GW --user alice --tool open_incident_issue --arg title="db down"
./mz policy disable 91_freeze-issue-creation
./mz logs gateway
```

**Expected:**
- bob's `tools visible` list does not include `open_incident_issue`, and the call prints `DENIED: access denied by policy for http://localhost:8000/mcp`.
- alice gets issue `#4242`.
- After the freeze, alice is denied too: the `forbid` beats `open-issue-commanders-only`.

**Real Keycard:** Console > Gateways. The same Cedar rules work, but use the bare upstream tool name and `resource.identifier` = the upstream URL. Make the MCP server accept only gateway tokens so agents cannot bypass it. Recipes exist for agentgateway, Kong, Azure APIM and Gravitee.
