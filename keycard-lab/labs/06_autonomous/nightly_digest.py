"""Labs 06 + 07: a background job with NO user present.

  --mode as_self      client credentials: the job acts as ITSELF (lab 06)
  --mode impersonate  acts AS an absent user, under policy (lab 07)

  python labs/06_autonomous/nightly_digest.py --mode as_self
  python labs/06_autonomous/nightly_digest.py --mode impersonate --user alice@example.com
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import httpx

from common import settings
from common.tokens import show
from keycardai.oauth import BasicAuth, Client, ClientConfig, ClientCredentialsRequest
from keycardai.oauth.exceptions import OAuthHttpError, OAuthProtocolError


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["as_self", "impersonate"], default="as_self")
    ap.add_argument("--user", default="alice@example.com", help="impersonate: the absent user")
    ap.add_argument("--resource", default=settings.GITHUB)
    a = ap.parse_args()
    cid, secret = settings.creds("nightly-digest")
    try:
        with Client(settings.ZONE_URL, auth=BasicAuth(cid, secret),
                    config=ClientConfig(enable_metadata_discovery=True, auto_register_client=False)) as kc:
            if a.mode == "as_self":
                tok = kc.client_credentials_grant(ClientCredentialsRequest(resource=a.resource))
            else:
                # NEVER take this identifier from model/tool input: only from trusted job config.
                tok = kc.impersonate(user_identifier=a.user, resource=a.resource)
    except OAuthProtocolError as e:
        print(f"REFUSED: {e.error}: {e.error_description}")
        sys.exit(2)
    except OAuthHttpError as e:
        print(f"REFUSED: HTTP {e.status_code}: {e.response_body}")
        sys.exit(2)
    show(f"credential for {a.resource} ({a.mode})", tok.access_token)
    if a.resource == settings.GITHUB:
        r = httpx.get(f"{settings.GITHUB_API_BASE}/repos/{settings.DEMO_REPO}/pulls",
                      headers={"Authorization": f"Bearer {tok.access_token}"})
        print(f"\nGitHub /pulls -> HTTP {r.status_code}: {[p['title'] for p in r.json()] if r.status_code == 200 else r.text}")
        who = httpx.get(f"{settings.GITHUB_API_BASE}/user", headers={"Authorization": f"Bearer {tok.access_token}"})
        print(f"GitHub /user  -> acting as {who.json().get('login') if who.status_code == 200 else who.status_code}")


if __name__ == "__main__":
    main()
