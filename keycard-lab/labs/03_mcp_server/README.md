# Lab 03: protect an MCP server

**Proves:** wrapping an MCP server with `AuthProvider` gives you three things. Spec-compliant OAuth discovery, a 401 challenge, and verification of every bearer token. A tool then knows exactly which user is calling.

Server: `github_mcp.py` (port 8000, started by `./mz up`). Client: `mcp_client.py`.

```bash
.venv/bin/python labs/03_mcp_server/mcp_client.py --user alice            # PKCE sign-in, list tools, call whoami
.venv/bin/python labs/03_mcp_server/mcp_client.py --user alice --tool ping
curl -i -X POST localhost:8000/mcp                                          # 401 + WWW-Authenticate
curl -s localhost:8000/.well-known/oauth-protected-resource/mcp             # RFC 9728 metadata
```

**Expected:** `whoami` returns `sub: alice`, `keycard_app_id: oncall-cli`, `aud: http://localhost:8000/mcp`, and the `sid`/`jti`.

**Try:**
- Remove `audience=` from `AuthProvider` and restart (`./mz restart`). The SDK warns that any token minted in the zone will now be accepted. Put it back.
- Connect a real MCP client. **MCP Inspector:** `npx @modelcontextprotocol/inspector`, URL `http://localhost:8000/mcp`. **Claude Code:** `claude mcp add --transport http incident http://localhost:8000/mcp`. They register themselves (DCR) with the mock zone, and the mock zone's picker page asks who you are.

**Pitfall:** always set `audience`. Without it the verifier accepts a token minted for any resource in the zone.
