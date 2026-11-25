"""Mock Keycard zone: a LOCAL SIMULATOR for learning and offline testing.

This is NOT Keycard. It imitates the parts of a Keycard zone that the labs
exercise, so the real Keycard SDKs (keycardai-mcp, -a2a, -oauth, -langchain)
can run end to end on your laptop with no account:

  * OAuth 2.1 authorization server metadata + JWKS (RS256 JWTs)
  * authorization code + PKCE sign-in with a user picker (public clients)
  * client_credentials (an app acting as itself)
  * RFC 8693 token exchange (delegation) and substitute-user (impersonation)
  * client auth: client secret (Basic or form) or a workload-identity JWT
  * Cedar policy decisions (cedarpy) on every issuance, user AND app
  * brokered third-party tokens (a fake GitHub) that need a prior user grant
  * sessions (sid), token ids (jti), audit log, grant revocation
  * a fake GitHub API at /github so nothing leaves your machine

Behaviour that follows the Keycard docs/field guide (default deny, forbid wins,
audience binding, access_denied vs insufficient_authorization, impersonation
preconditions, revocation does not kill held tokens) is reproduced as
described there. Exact wire details (error bodies, act claim, audit fields)
are the simulator's own choices; do not treat them as Keycard's contract.

Run:  .venv/bin/python mockzone/server.py      (listens on :9000)
"""

from __future__ import annotations

import base64
import hashlib
import html
import json
import os
import secrets
import threading
import time
import uuid
from pathlib import Path
from urllib.parse import urlencode

import cedarpy
import jwt
import uvicorn
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Route

HERE = Path(__file__).resolve().parent
PORT = int(os.getenv("MOCKZONE_PORT", "9000"))
ZONE = os.getenv("MOCKZONE_URL", f"http://localhost:{PORT}").rstrip("/")
STATE_DIR = HERE / ".state"
POLICY_ACTIVE = HERE / "policies" / "active"
POLICY_AVAILABLE = HERE / "policies" / "available"
DEFAULT_TTL = int(os.getenv("MOCKZONE_TOKEN_TTL", "3600"))

TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
TT_ACCESS = "urn:ietf:params:oauth:token-type:access_token"
TT_SUBSTITUTE = "urn:keycard:params:oauth:token-type:substitute-user"  # informational

LOCK = threading.RLock()


# --------------------------------------------------------------------------- keys
def _load_or_create_key(name: str) -> rsa.RSAPrivateKey:
    STATE_DIR.mkdir(exist_ok=True)
    path = STATE_DIR / f"{name}.pem"
    if path.exists():
        return serialization.load_pem_private_key(path.read_bytes(), password=None)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    path.chmod(0o600)
    return key


ZONE_KEY = _load_or_create_key("zone-signing-key")
ZONE_KID = "mockzone-1"
PLATFORM_KEY = _load_or_create_key("platform-signing-key")  # fake k8s/cloud OIDC issuer
PLATFORM_ISS = f"{ZONE}/mock/platform"


def _jwk(key: rsa.RSAPrivateKey, kid: str) -> dict:
    j = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    j.update({"kid": kid, "use": "sig", "alg": "RS256"})
    return j


# --------------------------------------------------------------------------- directory + state
def load_directory() -> dict:
    raw = (HERE / "zone.json").read_text().replace("{ZONE}", ZONE)
    return json.loads(raw)


DIR = load_directory()
STATE_FILE = STATE_DIR / "state.json"


def fresh_state() -> dict:
    return {
        "group_members": {
            g: sorted(u for u, d in DIR["users"].items() if g in d["groups"])
            for g in {g for d in DIR["users"].values() for g in d["groups"]}
        },
        "grants": [dict(g, granted_at=int(time.time())) for g in DIR["seed_grants"]],
        "dynamic_clients": {},
        "brokered_tokens": {},  # token -> {user|app, exp}
        "audit": [],
    }


def load_state() -> dict:
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text())
    return fresh_state()


STATE = load_state()
CODES: dict[str, dict] = {}  # authorization codes (in memory)


def save_state() -> None:
    STATE_FILE.write_text(json.dumps(STATE, indent=1))


def audit(event: str, **fields) -> dict:
    entry = {"ts": time.strftime("%H:%M:%S"), "event": event}
    entry.update({k: v for k, v in fields.items() if v is not None})
    with LOCK:
        STATE["audit"].append(entry)
        STATE["audit"] = STATE["audit"][-2000:]
        save_state()
    print(f"[audit] {json.dumps(entry)}", flush=True)
    return entry


def has_grant(user: str, resource: str) -> bool:
    return any(g["user"] == user and g["resource"] == resource for g in STATE["grants"])


def all_apps() -> dict:
    return {**DIR["applications"], **STATE["dynamic_clients"]}


# --------------------------------------------------------------------------- Cedar
def _policy_text() -> tuple[str, dict[str, str]]:
    """Concatenate active policies (re-read every request: edits apply on the next call)."""
    parts = [p.read_text() for p in sorted(POLICY_ACTIVE.glob("*.cedar"))]
    text = "\n".join(parts)
    ids: dict[str, str] = {}
    if text.strip():
        js = json.loads(cedarpy.policies_to_json_str(text))
        for pid, pol in js.get("staticPolicies", {}).items():
            ids[pid] = pol.get("annotations", {}).get("id", pid)
    return text, ids


def _uid(t: str, i: str) -> dict:
    return {"__entity": {"type": f"Keycard::{t}", "id": i}}


def _entities(principal: tuple[str, str], resource: str, subject: str | None) -> list:
    ents = []
    users = {principal[1]} if principal[0] == "User" else set()
    if subject:
        users.add(subject)
    for u in users:
        groups = [g for g, m in STATE["group_members"].items() if u in m]
        ents.append({
            "uid": {"type": "Keycard::User", "id": u},
            "attrs": {"identifier": DIR["users"][u]["email"], "email": DIR["users"][u]["email"]},
            "parents": [{"type": "Keycard::Group", "id": g} for g in groups],
        })
    if principal[0] == "Application":
        app = all_apps()[principal[1]]
        ents.append({
            "uid": {"type": "Keycard::Application", "id": principal[1]},
            "attrs": {
                "identifier": principal[1],
                "name": app.get("name", principal[1]),
                "credential_type": app.get("credential_type", "password"),
                "traits": app.get("traits", []),
            },
            "parents": [],
        })
    res = DIR["resources"].get(resource, {"name": resource, "scopes": []})
    ents.append({
        "uid": {"type": "Keycard::Resource", "id": resource},
        "attrs": {"identifier": resource, "name": res["name"], "scopes": res.get("scopes", [])},
        "parents": [],
    })
    ents.append({
        "uid": {"type": "Keycard::Action", "id": "mcp::tools/list"},
        "attrs": {},
        "parents": [{"type": "Keycard::Action", "id": "MCPProtocol"}],
    })
    return ents


def decide(principal: tuple[str, str], resource: str, *, action: str = "any",
           on_behalf: bool = False, impersonate: bool = False,
           subject: str | None = None) -> tuple[bool, list[str], list[str]]:
    """Evaluate one Cedar request. Returns (allowed, matching policy ids, errors)."""
    text, ids = _policy_text()
    if not text.strip():
        return False, [], ["no active policies: default deny"]
    ctx: dict = {"on_behalf": on_behalf, "impersonate": impersonate, "resource": _uid("Resource", resource)}
    if subject:
        ctx["subject"] = _uid("User", subject)
        ctx["subject_claims"] = {"email": DIR["users"][subject]["email"]}
    req = {
        "principal": f'Keycard::{principal[0]}::"{principal[1]}"',
        "action": f'Keycard::Action::"{action}"',
        "resource": f'Keycard::Resource::"{resource}"',
        "context": ctx,
    }
    r = cedarpy.is_authorized(req, text, _entities(principal, resource, subject))
    reasons = [ids.get(p, p) for p in r.diagnostics.reasons]
    return r.decision == cedarpy.Decision.Allow, reasons, [str(e) for e in r.diagnostics.errors]


def check_delegated(app: str, user: str, resource: str, action: str = "any",
                    impersonate: bool = False) -> tuple[bool, dict]:
    """Delegated request: BOTH the user and the application must be permitted."""
    u_ok, u_why, _ = decide(("User", user), resource, action=action, on_behalf=not impersonate,
                            impersonate=impersonate, subject=user)
    a_ok, a_why, _ = decide(("Application", app), resource, action=action, on_behalf=not impersonate,
                            impersonate=impersonate, subject=user)
    return u_ok and a_ok, {"user": {"allowed": u_ok, "policies": u_why},
                           "application": {"allowed": a_ok, "policies": a_why}}


# --------------------------------------------------------------------------- tokens
def mint(*, sub: str, sub_profile: str, app: str, client_id: str, aud: str,
         sid: str | None, ttl: int | None = None, act: dict | None = None,
         extra: dict | None = None) -> tuple[str, dict]:
    now = int(time.time())
    res = DIR["resources"].get(aud, {})
    ttl = ttl if ttl is not None else res.get("token_ttl", DEFAULT_TTL)
    claims = {
        "iss": ZONE, "sub": sub, "sub_profile": sub_profile, "keycard_app_id": app,
        "client_id": client_id, "aud": aud, "scope": " ".join(res.get("scopes", [])),
        "iat": now, "exp": now + ttl, "jti": "tok-" + secrets.token_hex(4),
    }
    if sid:
        claims["sid"] = sid
    if act:
        claims["act"] = act
    if extra:
        claims.update(extra)
    tok = jwt.encode(claims, ZONE_KEY, algorithm="RS256", headers={"kid": ZONE_KID})
    return tok, claims


def verify_zone_token(token: str) -> dict:
    return jwt.decode(token, ZONE_KEY.public_key(), algorithms=["RS256"], issuer=ZONE,
                      options={"verify_aud": False})


def broker(resource: str, *, user: str | None = None, app: str | None = None) -> tuple[str, int]:
    """Hand out a provider token (simulates Keycard brokering GitHub)."""
    provider = DIR["resources"][resource]["brokered"]
    who = user or f"app:{app}"
    tok = f"gho_mock_{who.replace(':', '_')}_{secrets.token_hex(6)}"
    exp = int(time.time()) + 3600
    with LOCK:
        STATE["brokered_tokens"][tok] = {"provider": provider, "user": user, "app": app, "exp": exp}
        save_state()
    return tok, 3600


def oauth_error(error: str, desc: str, status: int = 400, **extra) -> JSONResponse:
    return JSONResponse({"error": error, "error_description": desc, **extra}, status_code=status)


def token_response(tok: str, ttl: int, issued_type: str = TT_ACCESS, scope: str = "") -> JSONResponse:
    body = {"access_token": tok, "token_type": "Bearer", "expires_in": ttl,
            "issued_token_type": issued_type}
    if scope:
        body["scope"] = scope
    return JSONResponse(body, headers={"Cache-Control": "no-store"})


# --------------------------------------------------------------------------- client authentication
class ClientAuthError(Exception):
    pass


def authenticate_client(request: Request, form) -> tuple[str, dict]:
    """Returns (app_id, app). Supports Basic, client_secret_post, jwt-bearer workload assertions,
    and public clients (client_id only)."""
    apps = all_apps()
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("basic "):
        cid, _, secret = base64.b64decode(auth[6:]).decode().partition(":")
        app = apps.get(cid)
        if not app or not app.get("secret") or not secrets.compare_digest(app["secret"], secret):
            raise ClientAuthError("bad client id or secret")
        return cid, app
    if form.get("client_assertion_type") == JWT_BEARER:
        assertion = form.get("client_assertion", "")
        try:
            claims = jwt.decode(assertion, PLATFORM_KEY.public_key(), algorithms=["RS256"],
                                audience=ZONE, issuer=PLATFORM_ISS)
        except jwt.PyJWTError as e:
            raise ClientAuthError(f"workload assertion rejected: {e}")
        for aid, app in apps.items():
            wi = app.get("workload_identity")
            if wi and wi["issuer"] == claims["iss"] and wi["subject"] == claims["sub"]:
                return aid, app
        raise ClientAuthError(f"no application is bound to workload {claims['sub']}")
    cid = form.get("client_id")
    if cid and cid in apps:
        app = apps[cid]
        if app.get("credential_type") == "public":
            return cid, app
        if form.get("client_secret") and secrets.compare_digest(app.get("secret", ""), form["client_secret"]):
            return cid, app
    raise ClientAuthError("client authentication required")


# --------------------------------------------------------------------------- endpoints: discovery
async def as_metadata(request: Request) -> JSONResponse:
    return JSONResponse({
        "issuer": ZONE,
        "authorization_endpoint": f"{ZONE}/oauth/authorize",
        "token_endpoint": f"{ZONE}/oauth/token",
        "registration_endpoint": f"{ZONE}/oauth/register",
        "jwks_uri": f"{ZONE}/openidconnect/jwks",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "client_credentials", TOKEN_EXCHANGE],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post",
                                                  "private_key_jwt", "none"],
        "scopes_supported": ["openid"],
    })


async def jwks(request: Request) -> JSONResponse:
    return JSONResponse({"keys": [_jwk(ZONE_KEY, ZONE_KID)]})


# --------------------------------------------------------------------------- endpoints: DCR
async def register(request: Request) -> JSONResponse:
    body = await request.json()
    cid = "dcr-" + secrets.token_hex(4)
    client = {"name": body.get("client_name", cid), "credential_type": "public",
              "registration_method": "dcr", "redirect_uris": body.get("redirect_uris", []),
              "consent": "explicit"}
    with LOCK:
        STATE["dynamic_clients"][cid] = client
        save_state()
    audit("client_registered", app=cid, name=client["name"])
    return JSONResponse({"client_id": cid, "client_name": client["name"],
                         "redirect_uris": client["redirect_uris"],
                         "grant_types": ["authorization_code", "refresh_token"],
                         "token_endpoint_auth_method": "none"}, status_code=201)


# --------------------------------------------------------------------------- endpoints: authorize (PKCE)
PICKER = """<!doctype html><meta charset=utf-8><title>Mock zone sign-in</title>
<style>body{{font:16px system-ui;max-width:520px;margin:60px auto;padding:0 16px}}
a.u{{display:block;padding:12px 16px;margin:8px 0;border:2px solid #333;border-radius:10px;text-decoration:none;color:inherit}}
a.u:hover{{background:#f3f3f3}} .n{{color:#666;font-size:14px}}</style>
<h2>Mock Keycard zone: sign in</h2>
<p class=n>Local simulator. Pick who you are (no passwords). Real Keycard sends you to your IdP here.</p>
<p><b>{app}</b> wants a token for <code>{resource}</code></p>{users}"""


async def authorize(request: Request) -> Response:
    q = dict(request.query_params)
    cid, redirect_uri, state = q.get("client_id"), q.get("redirect_uri"), q.get("state", "")
    resource = q.get("resource") or ""
    app = all_apps().get(cid or "")
    if not app:
        return HTMLResponse(f"unknown client_id {html.escape(str(cid))}", status_code=400)
    # Exact match against registered redirect URIs (never redirect anywhere else: no open redirect).
    if redirect_uri not in app.get("redirect_uris", []):
        return HTMLResponse("redirect_uri is not registered for this client", status_code=400)
    if q.get("code_challenge_method", "S256") != "S256" or not q.get("code_challenge"):
        return HTMLResponse("PKCE S256 code_challenge required", status_code=400)
    if resource and resource not in DIR["resources"]:
        return RedirectResponse(f"{redirect_uri}?{urlencode({'error': 'invalid_target', 'state': state})}")
    user = q.get("login_hint")
    if user and "@" in user:
        user = next((u for u, d in DIR["users"].items() if d["email"] == user), user)
    if not user or user not in DIR["users"]:
        base = str(request.url).split("&login_hint=")[0]
        links = "".join(
            f'<a class=u href="{html.escape(base)}&login_hint={u}"><b>{u}</b> '
            f'<span class=n>{d["email"]} · groups: {", ".join(g for g, m in STATE["group_members"].items() if u in m) or "none"}</span></a>'
            for u, d in DIR["users"].items())
        return HTMLResponse(PICKER.format(app=html.escape(app.get("name", cid)),
                                          resource=html.escape(resource or "(none)"), users=links))
    sid = "s-" + secrets.token_hex(3)
    audit("authentication", sid=sid, subject=user, app=cid, method="pkce")
    if resource:
        ok, why = check_delegated(cid, user, resource)
        audit("policy_decision", sid=sid, subject=user, app=cid, resource=resource,
              decision="permit" if ok else "deny", detail=why)
        if not ok:
            return RedirectResponse(f"{redirect_uri}?{urlencode({'error': 'access_denied', 'error_description': 'denied by policy', 'state': state})}")
    code = secrets.token_urlsafe(16)
    CODES[code] = {"client_id": cid, "user": user, "resource": resource, "sid": sid,
                   "challenge": q["code_challenge"], "redirect_uri": redirect_uri,
                   "exp": time.time() + 120}
    return RedirectResponse(f"{redirect_uri}?{urlencode({'code': code, 'state': state, 'iss': ZONE})}")


# --------------------------------------------------------------------------- endpoints: token
async def token(request: Request) -> Response:
    form = dict(await request.form())
    gt = form.get("grant_type")
    try:
        app_id, app = authenticate_client(request, form)
    except ClientAuthError as e:
        audit("client_auth_failed", error=str(e), grant_type=gt)
        return oauth_error("invalid_client", str(e), 401)

    if gt == "authorization_code":
        return _grant_code(form, app_id)
    if app.get("credential_type") == "public":
        return oauth_error("unauthorized_client", "public clients may only use authorization_code + PKCE")
    if gt == "client_credentials":
        return _grant_client_credentials(form, app_id)
    if gt == TOKEN_EXCHANGE:
        if form.get("subject_token_type", TT_ACCESS) != TT_ACCESS:
            return _grant_impersonation(form, app_id, app)
        return _grant_exchange(form, app_id)
    return oauth_error("unsupported_grant_type", f"grant_type {gt!r} not supported")


def _resource_of(form) -> str | None:
    return form.get("resource") or form.get("audience")


def _grant_code(form, app_id: str) -> Response:
    c = CODES.pop(form.get("code", ""), None)
    if not c or c["exp"] < time.time() or c["client_id"] != app_id:
        return oauth_error("invalid_grant", "unknown or expired code")
    if form.get("redirect_uri") != c["redirect_uri"]:
        return oauth_error("invalid_grant", "redirect_uri does not match the authorization request")
    verifier = form.get("code_verifier", "")
    calc = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    if calc != c["challenge"]:
        return oauth_error("invalid_grant", "PKCE verifier mismatch")
    aud = c["resource"] or f"{ZONE}/openid/connect/userinfo"
    tok, cl = mint(sub=c["user"], sub_profile="user", app=app_id, client_id=app_id, aud=aud, sid=c["sid"])
    audit("credential_issued", sid=c["sid"], jti=cl["jti"], subject=c["user"], app=app_id,
          resource=aud, grant="authorization_code+pkce")
    return token_response(tok, cl["exp"] - cl["iat"], scope=cl["scope"])


def _grant_client_credentials(form, app_id: str) -> Response:
    resource = _resource_of(form)
    if not resource or resource not in DIR["resources"]:
        return oauth_error("invalid_target", f"unknown resource {resource!r}")
    ok, why, _ = decide(("Application", app_id), resource)
    audit("policy_decision", app=app_id, resource=resource, grant="client_credentials",
          decision="permit" if ok else "deny", detail={"application": {"allowed": ok, "policies": why}})
    if not ok:
        return oauth_error("access_denied", f"policy does not permit {app_id} to reach {resource} as itself")
    if DIR["resources"][resource].get("brokered"):
        tok, ttl = broker(resource, app=app_id)
        audit("credential_issued", app=app_id, resource=resource, grant="client_credentials",
              credential="brokered/vaulted org credential")
        return token_response(tok, ttl)
    tok, cl = mint(sub=app_id, sub_profile="app", app=app_id, client_id=app_id, aud=resource, sid=None)
    audit("credential_issued", jti=cl["jti"], app=app_id, resource=resource, grant="client_credentials")
    return token_response(tok, cl["exp"] - cl["iat"], scope=cl["scope"])


def _grant_exchange(form, app_id: str) -> Response:
    resource = _resource_of(form)
    if not resource or resource not in DIR["resources"]:
        return oauth_error("invalid_target", f"unknown resource {resource!r}")
    try:
        subj = verify_zone_token(form.get("subject_token", ""))
    except jwt.PyJWTError as e:
        audit("exchange_rejected", app=app_id, resource=resource, error=f"subject_token: {e}")
        return oauth_error("invalid_grant", f"subject_token invalid: {e}")
    sid = subj.get("sid")
    # Simulator rule: an app may only exchange a token that was minted FOR it (aud = its own
    # resource). A token intercepted from, or forwarded by, another service is refused here too.
    own = all_apps().get(app_id, {}).get("resource")
    if subj.get("sub_profile") == "user" and subj.get("aud") != own:
        audit("exchange_rejected", sid=sid, app=app_id, resource=resource,
              error=f"subject_token aud {subj.get('aud')} is not {app_id}'s resource")
        return oauth_error("invalid_grant", f"subject_token was not issued for {app_id}")
    # An app's own token as subject: the app acts as itself across hops.
    if subj["sub_profile"] == "app":
        return _grant_client_credentials(form, app_id)
    user = subj["sub"]
    ok, why = check_delegated(app_id, user, resource)
    audit("policy_decision", sid=sid, subject=user, app=app_id, resource=resource,
          grant="token_exchange", decision="permit" if ok else "deny", detail=why)
    if not ok:
        return oauth_error("access_denied", f"policy denied {app_id} acting for {user} on {resource}")
    res = DIR["resources"][resource]
    if res.get("brokered"):
        if not has_grant(user, resource):
            audit("exchange_failed", sid=sid, subject=user, app=app_id, resource=resource,
                  error="insufficient_authorization")
            return oauth_error("insufficient_authorization",
                               f"{user} has not authorized {resource}",
                               authorization_url=f"{ZONE}/mock/connect?user={user}&resource={resource}")
        tok, ttl = broker(resource, user=user)
        audit("credential_issued", sid=sid, subject=user, app=app_id, resource=resource,
              grant="token_exchange", credential=f"brokered {res['brokered']} token")
        return token_response(tok, ttl)
    act = None
    if form.get("actor_token"):
        try:
            actor = verify_zone_token(form["actor_token"])
            act = {"sub": actor["sub"], **({"act": actor["act"]} if "act" in actor else {})}
        except jwt.PyJWTError:
            return oauth_error("invalid_grant", "actor_token invalid")
    tok, cl = mint(sub=user, sub_profile="user", app=app_id, client_id=app_id, aud=resource, sid=sid, act=act)
    audit("credential_issued", sid=sid, jti=cl["jti"], subject=user, app=app_id, resource=resource,
          grant="token_exchange")
    return token_response(tok, cl["exp"] - cl["iat"], scope=cl["scope"])


def _grant_impersonation(form, app_id: str, app: dict) -> Response:
    resource = _resource_of(form)
    if not resource or resource not in DIR["resources"]:
        return oauth_error("invalid_target", f"unknown resource {resource!r}")
    # substitute-user token: an UNSIGNED JWT naming the user. It proves nothing by itself.
    try:
        claims = jwt.decode(form.get("subject_token", ""), options={"verify_signature": False})
        ident = claims.get("sub") or claims.get("user_identifier") or claims.get("email")
    except jwt.PyJWTError:
        ident = form.get("subject_token")
    user = next((u for u, d in DIR["users"].items() if ident in (u, d["email"])), None)
    if not user:
        return oauth_error("invalid_grant", f"unknown user {ident!r}")
    if app.get("consent") != "implicit":
        audit("impersonation_denied", app=app_id, subject=user, resource=resource,
              error="application consent must be implicit")
        return oauth_error("access_denied", "impersonation requires application consent = implicit")
    ok, why = check_delegated(app_id, user, resource, impersonate=True)
    audit("policy_decision", subject=user, app=app_id, resource=resource, grant="impersonation",
          decision="permit" if ok else "deny", detail=why)
    if not ok:
        return oauth_error("access_denied", f"no policy permits {app_id} to impersonate {user} on {resource}")
    if not has_grant(user, resource):
        audit("exchange_failed", subject=user, app=app_id, resource=resource,
              error="insufficient_authorization")
        return oauth_error("insufficient_authorization", f"{user} never delegated {resource}",
                           authorization_url=f"{ZONE}/mock/connect?user={user}&resource={resource}")
    if DIR["resources"][resource].get("brokered"):
        tok, ttl = broker(resource, user=user)
        audit("credential_issued", subject=user, app=app_id, resource=resource, grant="impersonation",
              credential="brokered provider token")
        return token_response(tok, ttl)
    tok, cl = mint(sub=user, sub_profile="user", app=app_id, client_id=app_id, aud=resource,
                   sid=None, act={"sub": app_id})
    audit("credential_issued", jti=cl["jti"], subject=user, app=app_id, resource=resource,
          grant="impersonation")
    return token_response(tok, cl["exp"] - cl["iat"], scope=cl["scope"])


# --------------------------------------------------------------------------- fake GitHub API
def _github_caller(request: Request) -> dict | None:
    tok = request.headers.get("authorization", "").removeprefix("Bearer ").removeprefix("token ").strip()
    info = STATE["brokered_tokens"].get(tok)
    if not info or info["exp"] < time.time() or info.get("revoked_at_provider"):
        return None
    return info


def _gh_unauth() -> JSONResponse:
    return JSONResponse({"message": "Bad credentials"}, status_code=401)


async def gh_user(request: Request) -> JSONResponse:
    c = _github_caller(request)
    if not c:
        return _gh_unauth()
    login = c["user"] or c["app"]
    audit("api_call", provider="github", path="/user", as_user=c["user"], app=c["app"])
    return JSONResponse({"login": f"{login}-gh", "name": login, "public_repos": 3})


async def gh_repo_list(request: Request) -> JSONResponse:
    c = _github_caller(request)
    if not c:
        return _gh_unauth()
    owner, repo, kind = (request.path_params[k] for k in ("owner", "repo", "kind"))
    who = c["user"] or c["app"]
    audit("api_call", provider="github", path=f"/repos/{owner}/{repo}/{kind}", as_user=c["user"], app=c["app"])
    if request.method == "POST":
        body = await request.json()
        return JSONResponse({"number": 4242, "title": body.get("title"), "user": {"login": f"{who}-gh"},
                             "html_url": f"https://github.com/{owner}/{repo}/issues/4242"}, status_code=201)
    if kind == "commits":
        return JSONResponse([{"sha": secrets.token_hex(4), "commit": {"message": m, "author": {"name": a}}}
                             for m, a in [("fix: retry on 503", "dana"), ("feat: add circuit breaker", "eli"),
                                          ("chore: bump deps", "dana")]])
    if kind == "pulls":
        return JSONResponse([{"number": 17, "title": "Add rate limiter", "user": {"login": "eli"},
                              "draft": False, "created_at": "2026-11-20T09:00:00+00:00"}])
    return JSONResponse([{"number": n, "title": t, "state": "open", "labels": [{"name": "incident"}]}
                         for n, t in [(101, "checkout 5xx spike"), (102, "payments latency p99 > 2s")]])


# --------------------------------------------------------------------------- mock-only admin endpoints
async def mock_state(request: Request) -> JSONResponse:
    return JSONResponse({
        "zone": ZONE,
        "group_members": STATE["group_members"],
        "grants": STATE["grants"],
        "active_policies": sorted(p.name for p in POLICY_ACTIVE.glob("*.cedar")),
        "available_policies": sorted(p.name for p in POLICY_AVAILABLE.glob("*.cedar")),
        "applications": {k: {kk: vv for kk, vv in v.items() if kk != "secret"} for k, v in all_apps().items()},
        "resources": DIR["resources"],
    })


async def mock_group(request: Request) -> JSONResponse:
    g, op = request.path_params["group"], request.path_params["op"]
    user = request.query_params["user"]
    with LOCK:
        members = set(STATE["group_members"].setdefault(g, []))
        (members.add if op == "add" else members.discard)(user)
        STATE["group_members"][g] = sorted(members)
        save_state()
    audit("group_membership_changed", group=g, op=op, subject=user)
    return JSONResponse({"group": g, "members": STATE["group_members"][g]})


async def mock_grants(request: Request) -> JSONResponse:
    user, resource = request.query_params["user"], request.query_params["resource"]
    with LOCK:
        STATE["grants"] = [g for g in STATE["grants"] if not (g["user"] == user and g["resource"] == resource)]
        if request.method == "POST":
            STATE["grants"].append({"user": user, "resource": resource, "granted_at": int(time.time())})
        save_state()
    audit("grant_created" if request.method == "POST" else "grant_revoked", subject=user, resource=resource)
    return JSONResponse({"grants": STATE["grants"]})


async def mock_connect(request: Request) -> HTMLResponse:
    """Simulated 'connect your GitHub account' consent page (the brokered provider OAuth dance)."""
    user, resource = request.query_params["user"], request.query_params["resource"]
    if request.method == "POST":
        await mock_grants(request)
        return HTMLResponse(f"<p>{html.escape(user)} connected {html.escape(resource)}. You can close this tab.</p>")
    return HTMLResponse(
        f"<form method=post><p>Allow Keycard to broker <b>{html.escape(resource)}</b> for "
        f"<b>{html.escape(user)}</b>?</p><button>Authorize</button></form>")


async def mock_provider_revoke(request: Request) -> JSONResponse:
    """Simulate revoking at the provider (GitHub settings): kills held brokered tokens for that user."""
    user = request.query_params["user"]
    n = 0
    with LOCK:
        for info in STATE["brokered_tokens"].values():
            if info.get("user") == user:
                info["revoked_at_provider"] = True
                n += 1
        save_state()
    audit("provider_tokens_revoked", provider="github", subject=user, count=n)
    return JSONResponse({"revoked": n})


async def mock_policy(request: Request) -> JSONResponse:
    name, op = request.path_params["name"], request.path_params["op"]
    name = name if name.endswith(".cedar") else name + ".cedar"
    src, dst = (POLICY_AVAILABLE, POLICY_ACTIVE) if op == "enable" else (POLICY_ACTIVE, POLICY_AVAILABLE)
    if (src / name).exists():
        (src / name).rename(dst / name)
    audit("policy_set_changed", policy=name, op=op)
    return JSONResponse({"active": sorted(p.name for p in POLICY_ACTIVE.glob("*.cedar"))})


async def mock_audit(request: Request) -> JSONResponse:
    sid = request.query_params.get("sid")
    rows = [e for e in STATE["audit"] if not sid or e.get("sid") == sid]
    return JSONResponse(rows[-int(request.query_params.get("limit", "200")):])


async def mock_decide(request: Request) -> JSONResponse:
    """Used by the mini gateway (lab 10): evaluate an MCP action for the caller's token,
    for the user AND the application acting for them (gateway semantics)."""
    body = await request.json()
    try:
        cl = verify_zone_token(body["token"])
    except jwt.PyJWTError as e:
        return JSONResponse({"allowed": False, "error": str(e)}, status_code=401)
    action, resource, app = body["action"], body["resource"], body.get("app") or cl["keycard_app_id"]
    if cl["sub_profile"] == "user":
        ok, why = check_delegated(app, cl["sub"], resource, action=action)
    else:
        ok, w, _ = decide(("Application", app), resource, action=action)
        why = {"application": {"allowed": ok, "policies": w}}
    audit("policy_decision", sid=cl.get("sid"), subject=cl["sub"], app=app, resource=resource,
          action=action, decision="permit" if ok else "deny", detail=why)
    return JSONResponse({"allowed": ok, "detail": why})


async def mock_platform_token(request: Request) -> JSONResponse:
    """Fake platform OIDC issuer: like a Kubernetes projected service-account token."""
    sa = request.query_params.get("sub", "system:serviceaccount:agents:workload-agent")
    now = int(time.time())
    tok = jwt.encode({"iss": PLATFORM_ISS, "sub": sa, "aud": ZONE, "iat": now, "exp": now + 600},
                     PLATFORM_KEY, algorithm="RS256", headers={"kid": "platform-1"})
    return JSONResponse({"token": tok})


async def mock_mint(request: Request) -> JSONResponse:
    """Test helper: mint an arbitrary zone token (e.g. already expired) for negative tests."""
    b = await request.json()
    tok, cl = mint(sub=b.get("sub", "alice"), sub_profile=b.get("sub_profile", "user"),
                   app=b.get("app", "oncall-cli"), client_id=b.get("app", "oncall-cli"),
                   aud=b["aud"], sid=b.get("sid", "s-test"), ttl=int(b.get("ttl", 60)))
    return JSONResponse({"access_token": tok, "claims": cl})


async def mock_reset(request: Request) -> JSONResponse:
    global STATE
    with LOCK:
        STATE = fresh_state()
        save_state()
        for p in POLICY_ACTIVE.glob("*.cedar"):
            if p.name.startswith("9"):  # lab-enabled extras go back to available/
                p.rename(POLICY_AVAILABLE / p.name)
    CODES.clear()
    return JSONResponse({"reset": True})


async def index(request: Request) -> HTMLResponse:
    return HTMLResponse(f"<h2>Mock Keycard zone</h2><p>Issuer <code>{ZONE}</code>. Local simulator.</p>"
                        "<ul><li><a href=/.well-known/oauth-authorization-server>AS metadata</a>"
                        "<li><a href=/openidconnect/jwks>JWKS</a><li><a href=/mock/state>state</a>"
                        "<li><a href=/mock/audit>audit log</a></ul>")


routes = [
    Route("/", index),
    Route("/.well-known/oauth-authorization-server", as_metadata),
    Route("/.well-known/openid-configuration", as_metadata),
    Route("/openidconnect/jwks", jwks),
    Route("/oauth/register", register, methods=["POST"]),
    Route("/oauth/authorize", authorize),
    Route("/oauth/token", token, methods=["POST"]),
    Route("/github/user", gh_user),
    Route("/github/repos/{owner}/{repo}/{kind}", gh_repo_list, methods=["GET", "POST"]),
    Route("/mock/state", mock_state),
    Route("/mock/groups/{group}/{op:str}", mock_group, methods=["POST"]),
    Route("/mock/grants", mock_grants, methods=["POST", "DELETE"]),
    Route("/mock/connect", mock_connect, methods=["GET", "POST"]),
    Route("/mock/provider-revoke", mock_provider_revoke, methods=["POST"]),
    Route("/mock/policies/{name}/{op:str}", mock_policy, methods=["POST"]),
    Route("/mock/audit", mock_audit),
    Route("/mock/decide", mock_decide, methods=["POST"]),
    Route("/mock/platform/token", mock_platform_token),
    Route("/mock/mint", mock_mint, methods=["POST"]),
    Route("/mock/reset", mock_reset, methods=["POST"]),
]
app = Starlette(routes=routes)

if __name__ == "__main__":
    print(f"Mock Keycard zone (LOCAL SIMULATOR) issuer={ZONE}")
    uvicorn.run(app, host="127.0.0.1", port=PORT, log_level="warning")
