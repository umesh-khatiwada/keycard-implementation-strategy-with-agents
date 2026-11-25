# keycard-implementation-strategy-with-agents

How to give every AI agent its own identity, policy-checked access and short-lived credentials with [Keycard](https://docs.keycard.ai), explained and runnable.

| What | Where |
|---|---|
| **Field guide**: how a token travels through your agents, a data-flow map for each feature, pitfalls, the Gatekeeper quiz and an implementation prompt | [`Keycard Field Guide.md`](Keycard%20Field%20Guide.md) (open the `.html` version in a browser for the interactive diagrams) |
| **Hands-on lab**: 13 runnable labs, one per feature, using the real Keycard SDKs and a local mock zone, so no account is needed | [`keycard-lab/`](keycard-lab/README.md) |

## Quick start

```bash
cd keycard-lab
uv venv .venv -p 3.12 && uv pip install --python .venv/bin/python -r requirements.txt
./mz up                                            # local mock zone + MCP server + agents + gateway + egress proxy
.venv/bin/python labs/05_a2a/ask.py --user alice   # user -> orchestrator -> triage -> GitHub, one session
tests/run.sh                                       # 20 end-to-end checks against the mock zone
```

## Labs

| # | Feature |
|---|---|
| 01 | Core model: challenge, request, evaluate, credential, access |
| 02 | Agent identity without stored secrets (client secret, workload identity) |
| 03 | Protect an MCP server (`AuthProvider`) |
| 04 | Delegated access: call GitHub as the signed-in user (`@grant`) |
| 05 | Agent-to-agent delegation (A2A, RFC 8693 token exchange) |
| 06 | Autonomous access: an agent acting as itself (client credentials) |
| 07 | Impersonation: acting for an absent user |
| 08 | Framework integration: LangChain, a fresh token per tool call |
| 09 | Cedar policies as code, with a test matrix |
| 10 | Gateway: per-tool allow/deny and a kill switch |
| 11 | Sandboxed agents: egress proxy (simulator; not yet released by Keycard) |
| 12 | CLI and coding agents (`keycard run`, `keycard.toml`; real account only) |
| 13 | Sessions, audit and revocation |

All labs run offline against the local mock zone. To use a real Keycard zone, set `KEYCARD_ZONE_URL` and the client ids in `keycard-lab/.env`. See the [real-zone checklist](keycard-lab/README.md#running-against-a-real-keycard-zone).

> The mock zone is a local simulator for learning, not Keycard. [What the mock proves and what it doesn't](keycard-lab/README.md#what-the-mock-proves-and-what-it-doesnt) lists what is real SDK behaviour, what follows the docs, and what the simulator invents.
