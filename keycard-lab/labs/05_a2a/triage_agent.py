"""Triage agent (port 8002). Accepts only tokens with aud = http://localhost:8002.
It exchanges the token it received (subject = the user) for a GitHub
credential for that user, then reads incident issues AS the user.

Run:  .venv/bin/python labs/05_a2a/triage_agent.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import httpx
import uvicorn
from a2a.server.agent_execution import AgentExecutor

from common import settings
from common.a2a_app import agent_text, build_app
from common.tokens import claims
from keycardai.a2a import AgentServiceConfig, keycard_user
from keycardai.oauth import AsyncClient, BasicAuth, ClientConfig, TokenExchangeRequest
from keycardai.oauth.exceptions import OAuthProtocolError

cid, secret = settings.creds("triage-agent")
config = AgentServiceConfig(
    service_name="Triage agent", client_id=cid, client_secret=secret,
    identity_url=settings.TRIAGE_URL, zone_id=settings.ZONE_ID,
    authorization_server_url=settings.ZONE_URL,
    description="Reads open incident issues for the calling user", capabilities=["triage"],
)


class TriageExecutor(AgentExecutor):
    async def execute(self, context, event_queue):
        caller = keycard_user(context)
        if caller is None:
            raise PermissionError("unauthenticated")
        c = claims(caller.access_token) or {}
        hop = f"[triage] sub={c.get('sub')} via app={c.get('keycard_app_id')} sid={c.get('sid')} jti={c.get('jti')}"
        print(hop, flush=True)
        # Hop 3: exchange the token WE received (aud = triage) for a GitHub credential.
        try:
            async with AsyncClient(settings.ZONE_URL, auth=BasicAuth(cid, secret),
                                   config=ClientConfig(enable_metadata_discovery=True)) as kc:
                gh = await kc.exchange_token(TokenExchangeRequest(
                    subject_token=caller.access_token, resource=settings.GITHUB))
        except OAuthProtocolError as e:
            # access_denied = a policy said no; insufficient_authorization = user must connect first
            await event_queue.enqueue_event(agent_text(f"{hop}\nGitHub exchange refused: {e.error}: {e.error_description}"))
            return
        async with httpx.AsyncClient(timeout=15) as http:
            r = await http.get(f"{settings.GITHUB_API_BASE}/repos/{settings.DEMO_REPO}/issues",
                               headers={"Authorization": f"Bearer {gh.access_token}"})
        titles = [i["title"] for i in r.json()] if r.status_code == 200 else r.text
        await event_queue.enqueue_event(agent_text(
            f"{hop}\nTriage of '{context.get_user_input()}': open incidents {titles}"))

    async def cancel(self, context, event_queue):
        return None


app = build_app(config, TriageExecutor())

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8002, log_level="warning")
