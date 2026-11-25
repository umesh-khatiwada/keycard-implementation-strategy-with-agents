"""Get a USER token with OAuth 2.1 authorization code + PKCE (public client).

  python -m common.login --resource http://localhost:8001            # browser sign-in
  python -m common.login --resource http://localhost:8001 --user bob # mock zone: headless

Against a real zone this opens your browser (keycardai.oauth.pkce.authenticate)
and you sign in with your IdP. Against the mock zone, --user picks the person
without a browser (the mock zone accepts login_hint as the sign-in).
The token is written to .tokens/<user>-<resource>.jwt (gitignored) and its
claims are printed. The token itself is never printed.
"""
from __future__ import annotations

import argparse
import asyncio
import os
import re
import time
import sys
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import httpx

from common import settings
from common.tokens import claims, show
from keycardai.oauth.pkce import authenticate, begin_authorization, complete_authorization

TOKENS = settings.ROOT / ".tokens"
REDIRECT = "http://localhost:8765/callback"


async def headless_mock_login(user: str, resource: str) -> str:
    """Same PKCE flow the SDK runs, with the 'browser' step done by httpx."""
    redirect = await begin_authorization(client_id=settings.CLI_CLIENT_ID, redirect_uri=REDIRECT,
                                         resources=[resource], issuer=settings.ZONE_URL)
    async with httpx.AsyncClient() as http:
        r = await http.get(redirect.url + f"&login_hint={user}", follow_redirects=False)
    params = {k: v[0] for k, v in parse_qs(urlsplit(r.headers["location"]).query).items()}
    if "error" in params:
        raise SystemExit(f"sign-in refused: {params['error']} ({params.get('error_description', '')})")
    tok = await complete_authorization(callback_params=params, state=redirect.state,
                                       code_verifier=redirect.code_verifier,
                                       client_id=settings.CLI_CLIENT_ID, redirect_uri=REDIRECT,
                                       issuer=settings.ZONE_URL)
    return tok.access_token


async def get_user_token(resource: str, user: str | None = None) -> str:
    if user and settings.IS_MOCK:
        return await headless_mock_login(user, resource)
    tok = await authenticate(client_id=settings.CLI_CLIENT_ID, resource_url=resource,
                             issuer=settings.ZONE_URL, redirect_uri=REDIRECT)
    return tok.access_token


def token_path(user: str | None, resource: str) -> Path:
    slug = re.sub(r"[^a-z0-9]+", "-", resource.lower()).strip("-")
    return TOKENS / f"{user or 'me'}-{slug}.jwt"


def load_or_login(resource: str, user: str | None = None, fresh: bool = False) -> str:
    p = token_path(user, resource)
    if p.exists() and not fresh:
        cached = p.read_text().strip()
        exp = (claims(cached) or {}).get("exp", 0)
        if exp - time.time() > 30:  # reuse only while comfortably valid
            return cached
    tok = asyncio.run(get_user_token(resource, user))
    TOKENS.mkdir(mode=0o700, exist_ok=True)
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)  # never world-readable, even briefly
    with os.fdopen(fd, "w") as f:
        f.write(tok)
    return tok


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--resource", required=True)
    ap.add_argument("--user", help="mock zone only: alice | bob | carol")
    a = ap.parse_args()
    tok = load_or_login(a.resource, a.user, fresh=True)
    show(f"user token saved to {token_path(a.user, a.resource).relative_to(settings.ROOT)}", tok)


if __name__ == "__main__":
    sys.exit(main())
