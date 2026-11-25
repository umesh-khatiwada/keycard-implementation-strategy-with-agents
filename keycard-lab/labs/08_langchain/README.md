# Lab 08: framework integration (LangChain, a fresh token per tool call)

**Proves:** `KeycardGrantMiddleware` exchanges the run's identity at the tool-call boundary. The tool reads the token with `get_access_context()`, and the model never sees a credential.

```bash
.venv/bin/python labs/08_langchain/oncall_agent.py --as on_behalf --user alice
.venv/bin/python labs/08_langchain/oncall_agent.py --as on_behalf --user bob
.venv/bin/python labs/08_langchain/oncall_agent.py --as self
```

**Expected:**
- alice: `(read as alice-gh) checkout 5xx spike, ...`
- bob: `GitHub access not granted: {... 'code': 'insufficient_authorization' ...}`
- self: `(read as oncall-langchain-gh) ...`

The identity is an explicit choice made per run: `Access.on_behalf_of(user_token)`, `Access.as_self()` or `Access.impersonate(user)`. It is never a silent fallback.

**No LLM key needed:** `ScriptedModel` makes one tool call and then summarises. To use Claude, run `pip install langchain-anthropic`, set `ANTHROPIC_API_KEY`, and pass `--llm claude`.

**Also in the SDK:** `interrupt_on_auth=True` with `authorization_url=` turns a missing grant into a LangGraph interrupt that carries a consent link (needs a checkpointer). `keycardai.langchain.testing.mock_access_context` lets you unit-test tools with no zone. The same pattern exists for Pydantic AI (`keycardai-pydantic-ai`) and Temporal (`keycardai-temporal`).
