"""Lab 02: three ways an agent proves who it is, then gets an APP token (sub_profile=app).

  python labs/02_identity/identity_demo.py secret      # client id + secret (local dev)
  python labs/02_identity/identity_demo.py workload    # platform-issued OIDC token, NO secret
  python labs/02_identity/identity_demo.py ambiguous   # discover_credential refuses to guess

workload: the mock zone plays the platform (like a Kubernetes projected
service-account token). The token is written to a file, the SDK's
WorkloadIdentity(FileTokenSource) reads it and presents it as a client
assertion. The zone maps (issuer, subject) -> the 'workload-agent' Application.
"""
import asyncio
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import httpx

from common import settings
from common.tokens import show
from keycardai.oauth import AsyncClient, BasicAuth, ClientConfig, ClientCredentialsRequest, NoneAuth
from keycardai.oauth.exceptions import OAuthProtocolError
from keycardai.oauth.server.credentials import (
    CredentialDiscoveryError, FileTokenSource, WorkloadIdentity, discover_credential)

CFG = ClientConfig(enable_metadata_discovery=True, auto_register_client=False)


async def with_secret():
    cid, secret = settings.creds("nightly-digest")
    async with AsyncClient(settings.ZONE_URL, auth=BasicAuth(cid, secret), config=CFG) as kc:
        tok = await kc.client_credentials_grant(ClientCredentialsRequest(resource=settings.REPORTS))
    show(f"app token for {settings.REPORTS} (client secret)", tok.access_token)


async def with_workload():
    if not settings.IS_MOCK:
        raise SystemExit("workload mode simulates the platform with the mock zone; in production your "
                         "platform injects the token file (EKS Pod Identity, K8s projected SA token, ...).")
    platform_token = httpx.get(f"{settings.ZONE_URL}/mock/platform/token").json()["token"]
    fd, path = tempfile.mkstemp(prefix="keycard-lab-workload-")  # mode 0600, unique name
    try:
        with os.fdopen(fd, "w") as f:
            f.write(platform_token)
        show("platform identity token (what Kubernetes/EKS would mount)", platform_token,
             keys=("iss", "sub", "aud", "exp"))
        cred = WorkloadIdentity(FileTokenSource(token_file_path=path))
        fields = (await cred.client_authentication(issuer=settings.ZONE_URL, endpoint="")).form_fields
        async with AsyncClient(settings.ZONE_URL, auth=NoneAuth(), config=CFG) as kc:
            tok = await kc.client_credentials_grant(ClientCredentialsRequest(
                resource=settings.REPORTS, client_assertion=fields["client_assertion"],
                client_assertion_type=fields["client_assertion_type"]))
        show("app token (workload identity: no secret anywhere)", tok.access_token)
    finally:
        os.unlink(path)


def ambiguous():
    env = {"KEYCARD_CLIENT_ID": "x", "KEYCARD_CLIENT_SECRET": "y",
           "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE": "/var/run/token"}
    print("env:", env)
    try:
        cred = discover_credential(env)
        print("picked:", type(cred).__name__)
    except CredentialDiscoveryError as e:
        print("start-up fails instead of guessing:\n ", e)
    env["KEYCARD_APPLICATION_CREDENTIAL_TYPE"] = "client_secret"
    print("\nwith KEYCARD_APPLICATION_CREDENTIAL_TYPE=client_secret ->",
          type(discover_credential(env)).__name__)


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "secret"
    try:
        {"secret": lambda: asyncio.run(with_secret()), "workload": lambda: asyncio.run(with_workload()),
         "ambiguous": ambiguous}[mode]()
    except OAuthProtocolError as e:
        print(f"refused: {e.error}: {e.error_description}")
