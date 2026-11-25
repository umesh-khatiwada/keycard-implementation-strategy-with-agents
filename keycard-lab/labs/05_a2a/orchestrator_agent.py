"""Orchestrator agent (port 8001), user-facing. Accepts only aud = http://localhost:8001.
For each request it EXCHANGES the user's token for one bound to the triage
agent (DelegationClient: discover agent card -> RFC 8693 -> SendMessage).
It never forwards the inbound token.

Run:  .venv/bin/python labs/05_a2a/orchestrator_agent.py
"""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import httpx
import uvicorn
from a2a.server.agent_execution import AgentExecutor

from common import settings
from common.a2a_app import agent_text, build_app
from common.tokens import claims
from keycardai.a2a import AgentServiceConfig, DelegationClient, keycard_user

cid, secret = settings.creds("incident-orchestrator")
config = AgentServiceConfig(
    service_name="Incident orchestrator", client_id=cid, client_secret=secret,
    identity_url=settings.ORCH_URL, zone_id=settings.ZONE_ID,
    authorization_server_url=settings.ZONE_URL,
    description="User-facing incident orchestrator", capabilities=["incident"],
)
delegation = DelegationClient(config)
# Lab switch to SEE the audience check: forward the inbound token instead of exchanging it.
BAD_FORWARD = os.getenv("LAB_FORWARD_INBOUND_TOKEN") == "1"


class OrchestratorExecutor(AgentExecutor):
    async def execute(self, context, event_queue):
        caller = keycard_user(context)
        if caller is None:
            raise PermissionError("unauthenticated")
        c = claims(caller.access_token) or {}
        hop = f"[orchestrator] sub={c.get('sub')} via app={c.get('keycard_app_id')} sid={c.get('sid')} jti={c.get('jti')}"
        print(hop, flush=True)
        task = "Triage: " + context.get_user_input()
        try:
            if BAD_FORWARD:
                result = await delegation.invoke_service(settings.TRIAGE_URL, task, token=caller.access_token)
            else:
                result = await delegation.invoke_service(settings.TRIAGE_URL, task,
                                                         subject_token=caller.access_token)
            text = result["result"]
        except httpx.HTTPStatusError as e:
            text = f"triage call rejected: HTTP {e.response.status_code} {e.response.headers.get('www-authenticate', '')}"
        except Exception as e:  # token exchange denied, etc.
            text = f"delegation failed: {type(e).__name__}: {e}"
        await event_queue.enqueue_event(agent_text(f"{hop}\n{text}"))

    async def cancel(self, context, event_queue):
        return None


app = build_app(config, OrchestratorExecutor())

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8001, log_level="warning")
