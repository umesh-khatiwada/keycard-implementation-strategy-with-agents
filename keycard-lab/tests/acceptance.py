"""Acceptance suite against the MOCK zone. Run via tests/run.sh (starts and stops everything).

Each check maps to a guarantee from the field guide. Mock-only behaviour is
simulated; see README "What the mock proves and what it doesn't".
Labs 11 (egress proxy, unreleased) and 12 (CLI, real account only) are reported
as SKIPPED-in-pass/fail sense: 11 is exercised as a simulator check only.
"""
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from common import settings
from common.login import load_or_login
from common.tokens import claims

assert settings.IS_MOCK, "acceptance suite runs against the mock zone only"
Z, PY = settings.ZONE_URL, sys.executable
results = []
MCP_INIT = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}}
HDRS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}


def check(name, fn):
    try:
        fn()
        results.append(("PASS", name, ""))
    except AssertionError as e:
        results.append(("FAIL", name, str(e)))
    except Exception as e:  # noqa: BLE001
        results.append(("FAIL", name, f"{type(e).__name__}: {e}"))


def run(*args):
    return subprocess.run([PY, *map(str, args)], capture_output=True, text=True, cwd=ROOT, timeout=120)


def mcp_status(token):
    h = dict(HDRS)
    if token:
        h["Authorization"] = f"Bearer {token}"
    return httpx.post(settings.MCP_RESOURCE, json=MCP_INIT, headers=h)


# ---------------------------------------------------------------- 1. inbound protection
def t_no_token():
    for url in (settings.MCP_RESOURCE, f"{settings.ORCH_URL}/a2a/jsonrpc", f"{settings.TRIAGE_URL}/a2a/jsonrpc",
                settings.GATEWAY_RESOURCE):
        r = httpx.post(url, json={}, headers=HDRS)
        assert r.status_code == 401, f"{url} -> {r.status_code}"
        assert "resource_metadata" in r.headers.get("www-authenticate", ""), f"{url}: no resource_metadata"


def t_valid_token():
    assert mcp_status(load_or_login(settings.MCP_RESOURCE, "alice", fresh=True)).status_code == 200


def t_wrong_audience():
    tok = load_or_login(settings.ORCH_URL, "alice", fresh=True)   # minted for the orchestrator
    assert mcp_status(tok).status_code == 401, "MCP server accepted an orchestrator token"
    r = httpx.post(f"{settings.TRIAGE_URL}/a2a/jsonrpc", json={}, headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 401, "triage accepted an orchestrator token"


def t_expired():
    tok = httpx.post(f"{Z}/mock/mint", json={"aud": settings.MCP_RESOURCE, "ttl": -60}).json()["access_token"]
    assert mcp_status(tok).status_code == 401


def t_wrong_issuer():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    forged = jwt.encode({"iss": "https://evil.example", "sub": "alice", "aud": settings.MCP_RESOURCE,
                         "exp": int(time.time()) + 600}, key, algorithm="RS256", headers={"kid": "mockzone-1"})
    assert mcp_status(forged).status_code == 401
    forged2 = jwt.encode({"iss": Z, "sub": "alice", "aud": settings.MCP_RESOURCE, "exp": int(time.time()) + 600},
                         key, algorithm="RS256", headers={"kid": "mockzone-1"})
    assert mcp_status(forged2).status_code == 401, "token signed by a foreign key accepted"


def t_policy_signin_denied():
    try:
        load_or_login(settings.ORCH_URL, "carol", fresh=True)
        raise AssertionError("carol (no groups) got a token")
    except SystemExit as e:
        assert "access_denied" in str(e)


# ---------------------------------------------------------------- 2. delegation
def t_a2a_chain_one_sid():
    httpx.post(f"{Z}/mock/reset")
    out = run("labs/05_a2a/ask.py", "--user", "alice", "--fresh", "x").stdout
    assert "open incidents" in out, out[-400:]
    sid = claims(load_or_login(settings.ORCH_URL, "alice"))["sid"]
    issued = [e for e in httpx.get(f"{Z}/mock/audit", params={"sid": sid}).json() if e["event"] == "credential_issued"]
    apps = [e["app"] for e in issued]
    assert apps == ["oncall-cli", "incident-orchestrator", "triage-agent"], apps


def t_forwarding_inbound_token_fails():
    tok = load_or_login(settings.ORCH_URL, "alice")
    r = httpx.post(f"{settings.TRIAGE_URL}/a2a/jsonrpc", json={}, headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 401


def t_mcp_grant_delegated():
    out = run("labs/03_mcp_server/mcp_client.py", "--user", "alice", "--fresh", "--tool", "list_incident_issues").stdout
    assert "checkout 5xx spike" in out, out[-300:]


def t_mcp_grant_insufficient():
    out = run("labs/03_mcp_server/mcp_client.py", "--user", "bob", "--fresh", "--tool", "recent_commits").stdout
    assert "insufficient_authorization" in out, out[-300:]


def t_langchain_modes():
    a = run("labs/08_langchain/oncall_agent.py", "--as", "on_behalf", "--user", "alice").stdout
    s = run("labs/08_langchain/oncall_agent.py", "--as", "self").stdout
    assert "read as alice-gh" in a, a
    assert "read as oncall-langchain-gh" in s, s


def t_zone_strictness():
    from keycardai.oauth import BasicAuth, Client, ClientConfig, TokenExchangeRequest
    from keycardai.oauth.exceptions import OAuthProtocolError
    orch_token = load_or_login(settings.ORCH_URL, "alice")             # aud = orchestrator
    cid, secret = settings.creds("triage-agent")
    with Client(Z, auth=BasicAuth(cid, secret), config=ClientConfig(enable_metadata_discovery=True)) as kc:
        try:
            kc.exchange_token(TokenExchangeRequest(subject_token=orch_token, resource=settings.GITHUB))
            raise AssertionError("triage exchanged a token minted for the orchestrator")
        except OAuthProtocolError as e:
            assert e.error == "invalid_grant", e.error
    r = httpx.get(f"{Z}/oauth/authorize", params={"client_id": "oncall-cli", "redirect_uri": "https://evil.example/cb",
                                                    "code_challenge": "x", "code_challenge_method": "S256",
                                                    "login_hint": "alice"}, follow_redirects=False)
    assert r.status_code == 400, f"unregistered redirect_uri -> {r.status_code}"


# ---------------------------------------------------------------- 3. no-user paths
def t_as_self():
    r = run("labs/06_autonomous/nightly_digest.py", "--mode", "as_self")
    assert r.returncode == 0 and "acting as nightly-digest-gh" in r.stdout, r.stdout + r.stderr


def t_impersonation_rules():
    httpx.post(f"{Z}/mock/reset")
    r = run("labs/06_autonomous/nightly_digest.py", "--mode", "impersonate")
    assert "access_denied" in r.stdout, f"no policy should mean access_denied: {r.stdout}"
    httpx.post(f"{Z}/mock/policies/90_digest-may-impersonate/enable")
    r = run("labs/06_autonomous/nightly_digest.py", "--mode", "impersonate")
    assert "acting as alice-gh" in r.stdout, r.stdout + r.stderr
    r = run("labs/06_autonomous/nightly_digest.py", "--mode", "impersonate", "--user", "bob@example.com")
    assert "insufficient_authorization" in r.stdout, r.stdout
    httpx.post(f"{Z}/mock/policies/90_digest-may-impersonate/disable")


def t_workload_identity():
    out = run("labs/02_identity/identity_demo.py", "workload").stdout
    assert '"sub": "workload-agent"' in out and '"sub_profile": "app"' in out, out


# ---------------------------------------------------------------- 4. policy
def t_policy_matrix():
    r = run("labs/09_policies/policy_matrix.py")
    assert r.returncode == 0, r.stdout[-600:]


def t_gateway_tool_rules():
    gw = ["labs/03_mcp_server/mcp_client.py", "--url", settings.GATEWAY_RESOURCE]
    bob = run(*gw, "--user", "bob", "--fresh", "--tool", "open_incident_issue", "--arg", "title=x").stdout
    visible = next(l for l in bob.splitlines() if l.startswith("tools visible:"))
    assert "open_incident_issue" not in visible, f"tools/list not filtered for bob: {visible}"
    assert "DENIED" in bob, bob
    alice = run(*gw, "--user", "alice", "--fresh", "--tool", "open_incident_issue", "--arg", "title=x").stdout
    assert '"number": 4242' in alice, alice
    httpx.post(f"{Z}/mock/policies/91_freeze-issue-creation/enable")
    try:
        alice = run(*gw, "--user", "alice", "--tool", "open_incident_issue", "--arg", "title=x").stdout
        assert "DENIED" in alice, "forbid did not beat the commanders permit"
    finally:
        httpx.post(f"{Z}/mock/policies/91_freeze-issue-creation/disable")


# ---------------------------------------------------------------- 5. audit + revocation
def t_revocation_and_groups():
    r = run("labs/13_audit_revoke/scenario.py")
    out = r.stdout
    assert "next exchange -> insufficient_authorization" in out, out[-800:]
    assert "held token still works until it expires: True" in out
    assert "after revoking at the provider, held token works: False" in out
    assert "access_denied" in out.split("4. Bob")[1], out[-500:]


# ---------------------------------------------------------------- simulator-only (not Keycard behaviour)
def t_egress_simulator():
    out = run("labs/11_sandbox_proxy/sandboxed_agent.py").stdout
    for reason in ("no_matching_endpoint", "cleartext_not_forwarded", "private_address_denied"):
        assert reason in out, out
    assert "alice-gh" in out


def t_no_static_keys():
    import re
    pat = re.compile(r"(ghp_[A-Za-z0-9]{20,}|github_pat_|sk-ant-|AKIA[0-9A-Z]{16})")
    hits = [str(p) for p in ROOT.rglob("*") if p.is_file() and ".venv" not in p.parts and ".state" not in p.parts
            and p.name != "acceptance.py"  # this file contains the patterns themselves
            and p.suffix in {".py", ".json", ".toml", ".md", ".env", ".example", ".cedar"} and pat.search(p.read_text(errors="ignore"))]
    assert not hits, hits


CHECKS = [
    ("401 + resource_metadata without a token (MCP, both agents, gateway)", t_no_token),
    ("valid user token accepted", t_valid_token),
    ("token for agent A rejected by B (audience)", t_wrong_audience),
    ("expired token rejected", t_expired),
    ("wrong issuer / foreign signing key rejected", t_wrong_issuer),
    ("sign-in denied by policy for user without groups (access_denied)", t_policy_signin_denied),
    ("user -> orchestrator -> triage -> GitHub, one sid, 3 issuances", t_a2a_chain_one_sid),
    ("forwarding the inbound token to the next agent fails", t_forwarding_inbound_token_fails),
    ("[simulator] zone refuses foreign subject_token and unregistered redirect_uri", t_zone_strictness),
    ("MCP @grant reads GitHub as the user", t_mcp_grant_delegated),
    ("MCP @grant: user never connected -> insufficient_authorization", t_mcp_grant_insufficient),
    ("LangChain middleware: on_behalf_of vs as_self", t_langchain_modes),
    ("client credentials: job acts as itself", t_as_self),
    ("impersonation: denied without policy, works with it, needs prior delegation", t_impersonation_rules),
    ("workload identity: app token without any secret", t_workload_identity),
    ("Cedar decision matrix", t_policy_matrix),
    ("gateway: per-tool permit, tools/list filtering, forbid kill switch", t_gateway_tool_rules),
    ("revoke -> insufficient_authorization; held token lives; group removal -> access_denied", t_revocation_and_groups),
    ("[simulator] egress proxy allow list and deny reasons", t_egress_simulator),
    ("no static API keys in the repo", t_no_static_keys),
]

if __name__ == "__main__":
    httpx.post(f"{Z}/mock/reset")
    for name, fn in CHECKS:
        check(name, fn)
        s, n, why = results[-1]
        print(f"{s}  {n}" + (f"\n      {why}" if why else ""), flush=True)
    httpx.post(f"{Z}/mock/reset")
    print("\nSKIPPED  lab 12 (keycard CLI / keycard.toml): needs a real Keycard account")
    fails = sum(r[0] == "FAIL" for r in results)
    print(f"\n{len(results) - fails}/{len(results)} passed")
    sys.exit(1 if fails else 0)
