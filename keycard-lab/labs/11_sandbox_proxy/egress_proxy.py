"""Lab 11: SIMULATOR of Keycard's sandbox egress proxy (the real one is NOT YET RELEASED).

Real deployment: an init container installs iptables rules so ALL outbound TCP/DNS
from the agent's pod goes to a sidecar; UDP/QUIC is dropped. The agent holds no
credentials; the sidecar adds them on the wire.

This simulator is an explicit HTTP service instead of a transparent sidecar:
the agent requests  http://localhost:8200/<full target URL>
  e.g.  http://localhost:8200/https://api.github.com/repos/acme/checkout/issues

Decision order (one JSON audit line each, reason in X-Keycard-Deny-Reason):
  cleartext_not_forwarded   target is http://
  private_address_denied    localhost / private / link-local / metadata IPs
  no_matching_endpoint      host + port + longest path prefix not in egress.json
  exchange_denied           impersonation exchange for the sandbox user refused
  endpoint_allowed          credential written into the configured header (overwriting
                            anything the agent sent), request forwarded. Never logged.

Run:  .venv/bin/python labs/11_sandbox_proxy/egress_proxy.py
"""
import ipaddress
import json
import socket
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import httpx
import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from common import settings
from keycardai.oauth import AsyncClient, BasicAuth, ClientConfig
from keycardai.oauth.exceptions import OAuthProtocolError

CONF = json.loads((Path(__file__).parent / "egress.json").read_text())
CID, SECRET = settings.creds("egress-proxy")
_cache: dict[str, tuple[str, float]] = {}


def log(reason: str, **kw) -> None:
    print(json.dumps({"ts": time.strftime("%H:%M:%S"), "reason": reason, **kw}), flush=True)


def deny(reason: str, status: int = 403, **kw) -> Response:
    log(reason, **kw)
    return JSONResponse({"denied": reason}, status_code=status, headers={"X-Keycard-Deny-Reason": reason})


def is_private(host: str) -> bool:
    try:
        ips = {ai[4][0] for ai in socket.getaddrinfo(host, None)} if not host.replace(".", "").isdigit() else {host}
    except socket.gaierror:
        return False
    return any(ipaddress.ip_address(ip).is_private or ipaddress.ip_address(ip).is_loopback
               or ipaddress.ip_address(ip).is_link_local for ip in ips)


def match(host: str, port: int, path: str) -> dict | None:
    cands = [e for e in CONF["endpoints"] if e["host"] == host and e["port"] == port and path.startswith(e["path_prefix"])]
    return max(cands, key=lambda e: len(e["path_prefix"]), default=None)


async def credential(resource: str) -> str:
    tok, exp = _cache.get(resource, ("", 0))
    if exp > time.time() + 30:
        return tok
    async with AsyncClient(settings.ZONE_URL, auth=BasicAuth(CID, SECRET),
                           config=ClientConfig(enable_metadata_discovery=True)) as kc:
        r = await kc.impersonate(user_identifier=CONF["sandbox_user"], resource=resource)
    _cache[resource] = (r.access_token, time.time() + (r.expires_in or 300))
    return r.access_token


async def proxy(request: Request) -> Response:
    target = request.url.path[1:] + (f"?{request.url.query}" if request.url.query else "")
    u = urlsplit(target)
    host, path = u.hostname or "", u.path or "/"
    port = u.port or (443 if u.scheme == "https" else 80)
    meta = {"method": request.method, "host": host, "port": port, "path": path}
    if u.scheme != "https":
        return deny("cleartext_not_forwarded", **meta)
    if host == "localhost" or is_private(host) or host == "169.254.169.254":
        return deny("private_address_denied", **meta)
    ep = match(host, port, path)
    if not ep:
        return deny("no_matching_endpoint", **meta)
    headers = {k: v for k, v in request.headers.items() if k.lower() in ("accept", "content-type")}
    if ep["resource"]:
        try:
            tok = await credential(ep["resource"])
        except OAuthProtocolError as e:
            return deny("exchange_denied", error=e.error, **meta)
        inj = ep["inject"]
        headers[inj["header"]] = inj["template"].format(token=tok)  # overwrites the agent's header
    log("endpoint_allowed", credentialed=bool(ep["resource"]), **meta)
    if settings.IS_MOCK:
        if host != "api.github.com":
            return JSONResponse({"simulated": f"would forward to {target} (offline mode)"})
        target = settings.GITHUB_API_BASE + path + (f"?{u.query}" if u.query else "")
    async with httpx.AsyncClient(timeout=30) as http:
        r = await http.request(request.method, target, headers=headers, content=await request.body())
    return Response(r.content, status_code=r.status_code, headers={"content-type": r.headers.get("content-type", "")})


app = Starlette(routes=[Route("/{target:path}", proxy, methods=["GET", "POST", "PUT", "PATCH", "DELETE"])])

if __name__ == "__main__":
    print("Egress proxy SIMULATOR (Keycard's egress proxy is not yet released)")
    uvicorn.run(app, host="127.0.0.1", port=8200, log_level="warning")
