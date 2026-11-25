"""One place for every URL and credential the labs use.

Values come from .env (copy .env.example). Defaults point at the LOCAL MOCK
zone, so the labs run offline. Point KEYCARD_ZONE_URL at your real zone
(https://<zone-id>.keycard.cloud) and fill in the real client ids/secrets to
run the same code against Keycard.
"""
from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
# ./mz and tests/run.sh set KEYCARD_LAB_NO_DOTENV=1 so a real-zone .env never leaks into mock runs.
if os.getenv("KEYCARD_LAB_NO_DOTENV") != "1":
    load_dotenv(ROOT / ".env")

ZONE_URL = os.getenv("KEYCARD_ZONE_URL", "http://localhost:9000").rstrip("/")
ZONE_ID = os.getenv("KEYCARD_ZONE_ID", "mockzone")
IS_MOCK = ZONE_URL.startswith("http://localhost") or ZONE_URL.startswith("http://127.0.0.1")

# Resources (must match Resource identifiers in your zone)
MCP_URL = os.getenv("MCP_SERVER_URL", "http://localhost:8000/")
MCP_RESOURCE = os.getenv("MCP_RESOURCE", "http://localhost:8000/mcp")
ORCH_URL = os.getenv("ORCHESTRATOR_URL", "http://localhost:8001")
TRIAGE_URL = os.getenv("TRIAGE_URL", "http://localhost:8002")
GATEWAY_RESOURCE = os.getenv("GATEWAY_RESOURCE", "http://localhost:8100/mcp")
GITHUB = os.getenv("GITHUB_RESOURCE", "https://api.github.com")
REPORTS = os.getenv("REPORTS_RESOURCE", "https://reports.internal.example")
# Where HTTP calls for GitHub actually go. Mock: the fake GitHub inside the mock zone.
GITHUB_API_BASE = os.getenv("GITHUB_API_BASE", f"{ZONE_URL}/github" if IS_MOCK else GITHUB).rstrip("/")
DEMO_REPO = os.getenv("DEMO_REPO", "acme/checkout")

# Public client used for user sign-in (PKCE)
CLI_CLIENT_ID = os.getenv("CLI_CLIENT_ID", "oncall-cli")


def creds(app: str) -> tuple[str, str]:
    """Client id/secret of one application, from env <APP>_CLIENT_ID / <APP>_CLIENT_SECRET."""
    key = app.upper().replace("-", "_")
    defaults = {
        "GITHUB_MCP": "github-mcp-secret", "INCIDENT_ORCHESTRATOR": "orchestrator-secret",
        "TRIAGE_AGENT": "triage-secret", "NIGHTLY_DIGEST": "digest-secret",
        "ONCALL_LANGCHAIN": "langchain-secret", "MCP_GATEWAY": "gateway-secret",
        "EGRESS_PROXY": "egress-secret",
    }
    cid = os.getenv(f"{key}_CLIENT_ID", app)
    secret = os.getenv(f"{key}_CLIENT_SECRET", defaults.get(key, "") if IS_MOCK else "")
    if not secret:
        raise SystemExit(f"Set {key}_CLIENT_ID / {key}_CLIENT_SECRET in .env for {app}")
    return cid, secret

