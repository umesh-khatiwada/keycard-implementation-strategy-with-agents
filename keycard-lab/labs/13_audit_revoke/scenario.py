"""Lab 13: sessions, audit and revocation - the timeline from the field guide.

  python labs/13_audit_revoke/scenario.py

MOCK ZONE ONLY: it needs two distinct test users (alice, bob) and simulated
provider-side revocation. On a real zone, follow the manual steps in README.md.
Needs: ./mz up
"""
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import httpx

from common import settings
from common.login import load_or_login
from common.tokens import claims
from keycardai.oauth import BasicAuth, Client, ClientConfig, TokenExchangeRequest
from keycardai.oauth.exceptions import OAuthProtocolError

Z = settings.ZONE_URL
PY = sys.executable
ROOT = settings.ROOT


def h(t):
    print(f"\n\033[1m=== {t} ===\033[0m")


def admin(desc, method, path):
    httpx.request(method, f"{Z}{path}").raise_for_status()
    print(f"[admin] {desc}")


def exchange_for_github(user_token):
    cid, secret = settings.creds("github-mcp")
    with Client(Z, auth=BasicAuth(cid, secret), config=ClientConfig(enable_metadata_discovery=True)) as kc:
        return kc.exchange_token(TokenExchangeRequest(subject_token=user_token, resource=settings.GITHUB))


def gh_status(tok):
    return httpx.get(f"{settings.GITHUB_API_BASE}/user", headers={"Authorization": f"Bearer {tok}"}).status_code


def main():
    if not settings.IS_MOCK:
        raise SystemExit("Lab 13's script is mock-only. On a real zone do the steps in "
                         "labs/13_audit_revoke/README.md by hand in the Console.")
    httpx.post(f"{Z}/mock/reset")

    h("1. One user request, many hops, ONE session id")
    out = subprocess.run([PY, str(ROOT / "labs/05_a2a/ask.py"), "--user", "alice", "--fresh", "db is slow"],
                         capture_output=True, text=True).stdout
    print("\n".join(l for l in out.splitlines() if l.startswith("[") or "HTTP" in l))
    sid = claims(load_or_login(settings.ORCH_URL, "alice"))["sid"]
    if settings.IS_MOCK:
        print(f"\naudit for sid={sid}:")
        for e in httpx.get(f"{Z}/mock/audit", params={"sid": sid}).json():
            print(f"  {e['ts']} {e['event']:18} app={e.get('app', '-'):22} resource={e.get('resource', '-')}"
                  f" {e.get('decision', '')} {e.get('jti', '')}")

    h("2. The MCP server holds a GitHub credential for alice (issued 'at 09:50')")
    alice_mcp = load_or_login(settings.MCP_RESOURCE, "alice", fresh=True)
    held = exchange_for_github(alice_mcp).access_token
    print("held GitHub token works:", gh_status(held) == 200)

    h("3. Admin revokes alice's GitHub grant ('at 10:00')")
    admin("revoke alice's grant for https://api.github.com", "DELETE",
          f"/mock/grants?user=alice&resource={settings.GITHUB}")
    try:
        exchange_for_github(alice_mcp)
        print("next exchange: unexpectedly succeeded")
    except OAuthProtocolError as e:
        print(f"next exchange -> {e.error}   (NOT access_denied: alice must authorize again)")
    print("held token still works until it expires:", gh_status(held) == 200)
    admin("revoke alice's tokens at GitHub itself (provider side)", "POST", "/mock/provider-revoke?user=alice")
    print("after revoking at the provider, held token works:", gh_status(held) == 200)

    h("4. Bob is removed from oncall-engineers. He does NOT sign out.")
    bob = load_or_login(settings.ORCH_URL, "bob", fresh=True)
    admin("remove bob from group oncall-engineers", "POST", "/mock/groups/oncall-engineers/remove?user=bob")
    out = subprocess.run([PY, str(ROOT / "labs/05_a2a/ask.py"), "--user", "bob", "status?"],
                         capture_output=True, text=True).stdout
    print("\n".join(l for l in out.splitlines() if "delegation" in l or "HTTP" in l or "refused" in l))
    print("-> his still-valid token reaches the orchestrator, but the NEXT issuance (exchange to triage)\n"
          "   is evaluated against current group membership and denied. No re-login, no policy edit.")

    if settings.IS_MOCK:
        h("5. Restore")
        httpx.post(f"{Z}/mock/reset")
        print("mock zone reset (grants, groups, audit)")


if __name__ == "__main__":
    main()
