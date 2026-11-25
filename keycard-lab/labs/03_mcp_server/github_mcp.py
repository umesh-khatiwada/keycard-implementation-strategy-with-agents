"""Incident GitHub MCP server, protected by Keycard (labs 03, 04, 10).

* AuthProvider wraps the MCP app: it serves /.well-known/oauth-protected-resource,
  answers unauthenticated calls with 401 + WWW-Authenticate, and verifies every
  bearer token (JWKS signature, iss, exp, and aud == this server).
* @auth_provider.grant(GITHUB) runs an RFC 8693 token exchange per tool call:
  the caller's token -> a GitHub credential for that same user (lab 04).

Run:  .venv/bin/python labs/03_mcp_server/github_mcp.py     (port 8000)
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import httpx
import uvicorn
from mcp.server.mcpserver import Context, MCPServer

from common import settings
from common.tokens import claims
from keycardai.mcp.server.auth import AccessContext, AuthProvider, ClientSecret

GITHUB = settings.GITHUB

auth_provider = AuthProvider(
    zone_url=settings.ZONE_URL,
    mcp_server_name="Incident GitHub MCP",
    mcp_server_url=settings.MCP_URL,
    # ALWAYS set audience: only tokens minted for THIS server are accepted.
    audience=settings.MCP_RESOURCE,
    # The server's own identity, used for token exchange. In production prefer
    # workload identity (EKSWorkloadIdentity / WorkloadIdentity) - see lab 02.
    application_credential=ClientSecret(settings.creds("github-mcp")),
)
mcp = MCPServer("Incident GitHub MCP")


def _caller(ctx: Context) -> dict:
    user = ctx.request_context.request.user  # KeycardUser set by the auth middleware
    c = claims(user.access_token) or {}
    return {k: c.get(k) for k in ("sub", "sub_profile", "keycard_app_id", "aud", "sid", "jti")}


@mcp.tool()
def ping() -> str:
    """Health check that only answers authenticated callers."""
    return "pong - you are authenticated"


@mcp.tool()
def whoami(ctx: Context) -> dict:
    """Show the verified identity the server sees for this call."""
    return _caller(ctx)


async def _github(token: str, method: str, path: str, **kw) -> httpx.Response:
    async with httpx.AsyncClient(timeout=15) as http:
        return await http.request(method, f"{settings.GITHUB_API_BASE}{path}",
                                  headers={"Authorization": f"Bearer {token}",
                                           "Accept": "application/vnd.github+json"}, **kw)


@mcp.tool()
@auth_provider.grant(GITHUB)
async def recent_commits(access_ctx: AccessContext, ctx: Context, repo: str = settings.DEMO_REPO) -> dict:
    """Recent commits of a repo, read AS the calling user (delegated access)."""
    if access_ctx.has_errors():  # non-throwing by design: always check
        return {"error": "token exchange failed", "details": access_ctx.get_errors()}
    r = await _github(access_ctx.access(GITHUB).access_token, "GET", f"/repos/{repo}/commits")
    return {"status": r.status_code, "commits": r.json()}


@mcp.tool()
@auth_provider.grant(GITHUB)
async def list_incident_issues(access_ctx: AccessContext, ctx: Context, repo: str = settings.DEMO_REPO) -> dict:
    """Open incident issues of a repo, read AS the calling user."""
    if access_ctx.has_errors():
        return {"error": "token exchange failed", "details": access_ctx.get_errors()}
    r = await _github(access_ctx.access(GITHUB).access_token, "GET", f"/repos/{repo}/issues",
                      params={"labels": "incident"})
    return {"status": r.status_code, "issues": r.json()}


@mcp.tool()
@auth_provider.grant(GITHUB)
async def open_incident_issue(access_ctx: AccessContext, ctx: Context, title: str,
                              repo: str = settings.DEMO_REPO) -> dict:
    """Open an incident issue AS the calling user (a 'dangerous' write tool, see lab 10)."""
    if access_ctx.has_errors():
        return {"error": "token exchange failed", "details": access_ctx.get_errors()}
    r = await _github(access_ctx.access(GITHUB).access_token, "POST", f"/repos/{repo}/issues",
                      json={"title": title, "labels": ["incident"]})
    return {"status": r.status_code, "issue": r.json()}


app = auth_provider.app(mcp)

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="warning")
