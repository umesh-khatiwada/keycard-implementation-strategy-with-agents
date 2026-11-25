"""Lab 10: a MINI MCP gateway that mimics Keycard's Unified Access Gateway (MOCK ZONE ONLY).

Keycard's real gateway is a hosted product; you configure it in the Console.
This ~150-line stand-in shows the same enforcement model so you can test
per-tool Cedar rules locally:

  client --(token aud=gateway)--> gateway :8100/mcp --(exchanged token aud=upstream)--> MCP server :8000/mcp

  * tools/list : tools the caller may not call are removed from the list
  * tools/call : action = Keycard::Action::"mcp::tools/call::<tool>", checked for
                 the user AND the gateway application acting for them, BEFORE forwarding
  * denied     : JSON-RPC -32603 "access denied by policy for <upstream>" over HTTP 403
  * policies are re-read on every call: toggling a forbid applies immediately

Run:  .venv/bin/python labs/10_gateway/mini_gateway.py
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import httpx
import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from common import settings
from keycardai.oauth import AsyncClient, BasicAuth, ClientConfig, TokenExchangeRequest
from keycardai.oauth.exceptions import OAuthProtocolError
from keycardai.oauth.server.verifier import TokenVerifier

if not settings.IS_MOCK:
    raise SystemExit("mini_gateway uses the mock zone's decision endpoint. With a real zone use "
                     "Keycard's Unified Access Gateway (Console > Gateways) and the same Cedar policies.")

UPSTREAM = settings.MCP_RESOURCE                      # http://localhost:8000/mcp
SELF = settings.GATEWAY_RESOURCE                      # http://localhost:8100/mcp
CID, SECRET = settings.creds("mcp-gateway")
verifier = TokenVerifier(issuer=settings.ZONE_URL, audience=SELF)
_exchanged: dict[str, str] = {}
PASS_HEADERS = ("mcp-session-id", "mcp-protocol-version", "accept", "content-type", "last-event-id")


async def decide(token: str, action: str) -> tuple[bool, dict]:
    async with httpx.AsyncClient() as http:
        r = await http.post(f"{settings.ZONE_URL}/mock/decide",
                            json={"token": token, "action": action, "resource": UPSTREAM, "app": CID})
    body = r.json()
    return body.get("allowed", False), body


async def upstream_token(user_token: str) -> str:
    """Exchange the caller's gateway token for one bound to the upstream server."""
    if user_token not in _exchanged:
        async with AsyncClient(settings.ZONE_URL, auth=BasicAuth(CID, SECRET),
                               config=ClientConfig(enable_metadata_discovery=True)) as kc:
            tok = await kc.exchange_token(TokenExchangeRequest(subject_token=user_token, resource=UPSTREAM))
        _exchanged[user_token] = tok.access_token
    return _exchanged[user_token]


def denied(rpc_id, why: dict | str) -> JSONResponse:
    print(f"[gateway] DENY {json.dumps(why)}", flush=True)
    return JSONResponse({"jsonrpc": "2.0", "id": rpc_id,
                         "error": {"code": -32603, "message": f"access denied by policy for {UPSTREAM}"}},
                        status_code=403)


def _parse(resp: httpx.Response) -> tuple[dict | None, str]:
    ctype = resp.headers.get("content-type", "")
    if "text/event-stream" in ctype:
        for line in resp.text.splitlines():
            if line.startswith("data:"):
                return json.loads(line[5:]), "sse"
        return None, "sse"
    return (resp.json() if resp.content else None), "json"


async def mcp_endpoint(request: Request) -> Response:
    auth = request.headers.get("authorization", "")
    challenge = {"WWW-Authenticate": f'Bearer resource_metadata="http://localhost:8100/.well-known/oauth-protected-resource/mcp"'}
    if not auth.startswith("Bearer "):
        return Response("missing token", 401, headers=challenge)
    token = auth[7:]
    try:
        await verifier.verify_token(token)  # signature, iss, exp, aud == gateway
    except Exception as e:
        return Response(f"invalid token: {e}", 401, headers=challenge)

    raw = await request.body()
    msg = json.loads(raw) if raw else {}
    method, rpc_id = msg.get("method"), msg.get("id")
    if method == "tools/call":
        tool = msg["params"]["name"]
        ok, why = await decide(token, f"mcp::tools/call::{tool}")
        if not ok:
            return denied(rpc_id, {"tool": tool, **why})
        print(f"[gateway] ALLOW tools/call::{tool}", flush=True)
    elif method == "tools/list":
        ok, why = await decide(token, "mcp::tools/list")
        if not ok:
            return denied(rpc_id, why)

    try:
        up = await upstream_token(token)
    except OAuthProtocolError as e:
        return denied(rpc_id, {"exchange": e.error})
    headers = {k: v for k, v in request.headers.items() if k.lower() in PASS_HEADERS}
    headers["authorization"] = f"Bearer {up}"
    async with httpx.AsyncClient(timeout=60) as http:
        resp = await http.request(request.method, UPSTREAM, content=raw, headers=headers)
    out_headers = {k: v for k, v in resp.headers.items() if k.lower() in ("mcp-session-id", "content-type")}

    if method == "tools/list" and resp.status_code == 200:
        body, kind = _parse(resp)
        if body and "result" in body:
            allowed = []
            for t in body["result"].get("tools", []):
                if (await decide(token, f"mcp::tools/call::{t['name']}"))[0]:
                    allowed.append(t)
            print(f"[gateway] tools/list filtered -> {[t['name'] for t in allowed]}", flush=True)
            body["result"]["tools"] = allowed
            out_headers["content-type"] = "application/json"
            return JSONResponse(body, headers={k: v for k, v in out_headers.items() if k != "content-type"})
    return Response(resp.content, status_code=resp.status_code, headers=out_headers)


async def prm(request: Request) -> JSONResponse:
    return JSONResponse({"resource": SELF, "authorization_servers": [settings.ZONE_URL],
                         "bearer_methods_supported": ["header"]})


app = Starlette(routes=[
    Route("/mcp", mcp_endpoint, methods=["GET", "POST", "DELETE"]),
    Route("/.well-known/oauth-protected-resource/mcp", prm),
    Route("/.well-known/oauth-protected-resource", prm),
])

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8100, log_level="warning")
