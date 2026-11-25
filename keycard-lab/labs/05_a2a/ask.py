"""Alice (or bob/carol) asks the orchestrator something over A2A 1.0 JSON-RPC.

  python labs/05_a2a/ask.py --user alice "checkout is throwing 500s"
  python labs/05_a2a/ask.py --user alice --to http://localhost:8002 "..."   # wrong-audience test
"""
import argparse
import json
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import httpx

from common import settings
from common.login import load_or_login
from common.tokens import show


def send(url: str, token: str | None, text: str) -> httpx.Response:
    headers = {"A2A-Version": "1.0"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    body = {"jsonrpc": "2.0", "id": "1", "method": "SendMessage",
            "params": {"message": {"messageId": str(uuid.uuid4()), "role": "ROLE_USER", "parts": [{"text": text}]}}}
    return httpx.post(f"{url}/a2a/jsonrpc", json=body, headers=headers, timeout=60)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("text", nargs="?", default="checkout is throwing 500s")
    ap.add_argument("--user")
    ap.add_argument("--to", default=settings.ORCH_URL, help="agent to call")
    ap.add_argument("--no-token", action="store_true")
    ap.add_argument("--fresh", action="store_true")
    a = ap.parse_args()
    token = None
    if not a.no_token:
        # Token #1: audience = the ORCHESTRATOR (even when --to points elsewhere, to show rejection)
        token = load_or_login(settings.ORCH_URL, a.user, fresh=a.fresh)
        show("token #1 (user -> orchestrator)", token)
    r = send(a.to, token, a.text)
    print(f"\nHTTP {r.status_code}")
    if r.status_code != 200:
        print("WWW-Authenticate:", r.headers.get("www-authenticate"))
        print(r.text[:300])
        return
    body = r.json()
    if "error" in body:
        print(json.dumps(body["error"], indent=2))
        return
    res = body["result"]
    msg = res.get("message") or res.get("task", {}).get("status", {}).get("message") or res
    parts = msg.get("parts", []) if isinstance(msg, dict) else []
    print("\n".join(p.get("text", "") for p in parts) or json.dumps(res, indent=2))


if __name__ == "__main__":
    main()
