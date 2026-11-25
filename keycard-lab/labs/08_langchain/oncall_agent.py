"""Lab 08: LangChain agent with KeycardGrantMiddleware - a fresh token per tool call.

The model never sees a credential. At the tool-call boundary the middleware
exchanges the run's identity for a GitHub credential and the tool reads it
with get_access_context().

  python labs/08_langchain/oncall_agent.py --as on_behalf --user alice
  python labs/08_langchain/oncall_agent.py --as on_behalf --user bob     # bob never connected GitHub
  python labs/08_langchain/oncall_agent.py --as self                     # no user: the agent itself

No LLM key needed: a scripted chat model makes one tool call, then answers
with what the tool returned. Set ANTHROPIC_API_KEY and --llm claude to use a real model
(needs: pip install langchain-anthropic).
"""
import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import httpx
from langchain.agents import create_agent
from langchain.tools import tool
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
from langchain_core.outputs import ChatGeneration, ChatResult

from common import settings
from common.login import load_or_login
from keycardai.langchain import Access, KeycardGrantMiddleware, KeycardIdentity, get_access_context

GITHUB = settings.GITHUB
AGENT_RESOURCE = os.getenv("LANGCHAIN_AGENT_RESOURCE", "http://localhost:8300")


@tool
def list_incident_issues() -> str:
    """List open incident issues in the on-call repository."""
    access = get_access_context()
    if access.has_error():
        return f"Cannot reach GitHub: {access.get_error()}"
    if access.has_resource_error(GITHUB):
        return f"GitHub access not granted: {access.get_resource_error(GITHUB)}"
    token = access.access(GITHUB).access_token
    r = httpx.get(f"{settings.GITHUB_API_BASE}/repos/{settings.DEMO_REPO}/issues",
                  headers={"Authorization": f"Bearer {token}"})
    me = httpx.get(f"{settings.GITHUB_API_BASE}/user", headers={"Authorization": f"Bearer {token}"}).json()
    return f"(read as {me.get('login')}) " + ", ".join(i["title"] for i in r.json())


class ScriptedModel(BaseChatModel):
    """Deterministic stand-in for an LLM: call the tool once, then summarise its output."""

    @property
    def _llm_type(self) -> str:
        return "scripted"

    def bind_tools(self, tools, **kw):
        return self

    def _generate(self, messages, stop=None, run_manager=None, **kw):
        last = messages[-1]
        if isinstance(last, ToolMessage):
            msg = AIMessage(content=f"On-call summary: {last.content}")
        else:
            msg = AIMessage(content="", tool_calls=[{"name": "list_incident_issues", "args": {}, "id": "call-1"}])
        return ChatResult(generations=[ChatGeneration(message=msg)])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--as", dest="mode", choices=["on_behalf", "self"], default="on_behalf")
    ap.add_argument("--user", default="alice")
    ap.add_argument("--llm", choices=["scripted", "claude"], default="scripted")
    a = ap.parse_args()

    cid, secret = settings.creds("oncall-langchain")
    keycard = KeycardGrantMiddleware(zone_url=settings.ZONE_URL, resources=[GITHUB],
                                     client_id=cid, client_secret=secret, interrupt_on_auth=False)
    if a.llm == "claude":
        from langchain_anthropic import ChatAnthropic
        model = ChatAnthropic(model=os.getenv("ANTHROPIC_MODEL", "claude-sonnet-5-5"), max_tokens=1024)
    else:
        model = ScriptedModel()
    agent = create_agent(model, tools=[list_incident_issues], middleware=[keycard],
                         context_schema=KeycardIdentity,
                         system_prompt="You help the on-call engineer. Use tools, then summarise briefly.")

    if a.mode == "on_behalf":
        user_token = load_or_login(AGENT_RESOURCE, a.user)  # the user signed in to THIS agent
        identity = Access.on_behalf_of(user_token)
    else:
        identity = Access.as_self()  # explicit choice, never a silent fallback
    result = agent.invoke({"messages": [HumanMessage("Any open incidents?")]}, context=identity)
    print(result["messages"][-1].content)


if __name__ == "__main__":
    main()
