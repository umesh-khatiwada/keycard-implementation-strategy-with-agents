"""Lab 01: walk the core model by hand: challenge -> discover -> credential -> access.

Needs the mock zone and the MCP server (lab 03) running.
  python labs/01_core_model/explore.py --user alice
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import httpx

from common import settings
from common.login import load_or_login
from common.tokens import show

MCP_INIT = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                       "clientInfo": {"name": "lab01", "version": "1"}}}
HDRS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}


def step(n, title):
    print(f"\n=== {n}. {title} ===")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--user", default="alice")
    a = ap.parse_args()

    step(1, "Agent calls the resource with NO credential")
    r = httpx.post(settings.MCP_RESOURCE, json=MCP_INIT, headers=HDRS)
    print("HTTP", r.status_code)
    challenge = r.headers.get("www-authenticate", "")
    print("WWW-Authenticate:", challenge)

    step(2, "Follow resource_metadata (RFC 9728) to find the zone")
    meta_url = challenge.split('resource_metadata="')[1].split('"')[0]
    prm = httpx.get(meta_url).json()
    print(json.dumps(prm, indent=2))

    step(3, "Read the zone's authorization server metadata")
    zone = prm["authorization_servers"][0].rstrip("/")
    asm = httpx.get(f"{zone}/.well-known/oauth-authorization-server").json()
    print(json.dumps({k: asm[k] for k in ("issuer", "authorization_endpoint", "token_endpoint", "jwks_uri",
                                          "grant_types_supported")}, indent=2))

    step(4, "Request a credential for EXACTLY this resource (PKCE sign-in, policy evaluated)")
    tok = load_or_login(prm["resource"], a.user, fresh=True)
    show("issued token", tok)

    step(5, "Retry with the bearer token; the resource verifies signature, iss and aud")
    r = httpx.post(settings.MCP_RESOURCE, json=MCP_INIT, headers={**HDRS, "Authorization": f"Bearer {tok}"})
    print("HTTP", r.status_code, "(authenticated MCP initialize)")

    step(6, "Same token against a DIFFERENT resource (orchestrator): audience mismatch")
    r = httpx.post(f"{settings.ORCH_URL}/a2a/jsonrpc", json={}, headers={"Authorization": f"Bearer {tok}"})
    print("HTTP", r.status_code, r.headers.get("www-authenticate", "(orchestrator not running?)"))


if __name__ == "__main__":
    main()
