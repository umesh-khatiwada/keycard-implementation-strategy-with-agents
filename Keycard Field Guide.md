# Keycard field guide: how a token travels through your agents

Keycard gives every agent its own identity, checks a Cedar policy at every hop, and hands out short-lived, audience-bound tokens instead of stored API keys. Step through the full agent-to-agent relay below, then each feature has its own data-flow map, example code and pitfalls. A quiz and a ready-to-use implementation prompt close the page.

### Token in flight

```

```

Sample values. Changed claims are shown in red.

[Core model](#concepts) [Agent identity](#identity) [Protect MCP](#mcp) [Delegated access](#delegated) [Agent-to-agent](#a2a) [Autonomous](#autonomous) [Impersonation](#impersonation) [Frameworks](#frameworks) [Cedar policies](#policies) [Gateway](#gateway) [Sandbox proxy](#sandbox) [CLI & coding agents](#cli) [Audit & revoke](#audit) [Gatekeeper quiz](#game) [Implementation prompt](#prompt)

## Gatekeeper: would Keycard let this through?

Twelve requests from the incident demo. Pick what happens, then read why. Every answer follows a rule from the Keycard docs.

Score

0 / 0

Rules you are being tested on:

1. Tokens are bound to one audience; a resource rejects anyone else's.
2. Default deny, any `forbid` beats every `permit`.
3. `access_denied` means a rule said no; `insufficient_authorization` means the user must authorize first.
4. Revocation stops the next issuance, not tokens already held.
5. Pick the grant by who is present: PKCE, token exchange, client credentials, impersonation.

## The implementation prompt

Paste this into Claude Code (or any coding agent) at the root of your multi-agent project. Fill in the five lines under "My system" first. It walks the agent through every feature above in a safe order and ends with tests that prove each guarantee.

```
You are implementing Keycard (https://docs.keycard.ai) end to end in this repository so that every agent, MCP server and tool call uses runtime-issued, policy-checked, short-lived credentials. No static API keys may remain in code, env files or agent prompts when you finish.

My system (fill in):
- Agents and their roles: e.g. orchestrator (user-facing), triage worker, nightly report job
- How agents talk: A2A JSON-RPC / MCP / direct HTTP
- External resources: e.g. GitHub API, Slack API, Postgres, internal REST services
- Where it runs: e.g. Kubernetes on AWS (EKS), Vercel, local dev
- Identity provider for people: e.g. Okta / Entra ID / Google, and the groups that matter

Read first: docs.keycard.ai/llms.txt, then concepts, sdk/agent-to-agent, sdk/mcp, sdk/oauth, concepts/credentials, concepts/policies, reference/policy-schema, reference/token-claims. Use the official SDKs (Python: keycardai-a2a, keycardai-mcp or keycardai-fastmcp, keycardai-oauth, keycardai-starlette, keycardai-langchain / -pydantic-ai / -temporal; TypeScript: @keycardai/a2a, @keycardai/mcp, @keycardai/langchain). Check installed versions and real signatures before writing code; the A2A packages are pre-1.0.

Work in phases. After each phase, stop, show me the diff and a short test result.

Phase 0 - Inventory. List every place a credential is created, stored, read or passed (env vars, config, prompts, headers). Produce a table: caller -> callee, on whose behalf (user / agent itself / absent user), and the Keycard pattern that fits (PKCE sign-in, RFC 8693 token exchange, client credentials, impersonation, gateway, egress proxy). Write the Keycard Console setup checklist I must do by hand: zone, IdP, groups (SCIM if available), one Application per agent, one Resource per agent/MCP server/API with its exact identifier URL, credential providers for third-party APIs, application dependencies.

Phase 1 - Identity. Give each agent/server its own Keycard Application. Locally use ClientSecret from env; in production use workload identity for the platform above (EKSWorkloadIdentity / Kubernetes projected token / WebIdentity / cloud OIDC) so no secret exists. Rely on discover_credential env vars (KEYCARD_CLIENT_ID, KEYCARD_CLIENT_SECRET, KEYCARD_APPLICATION_CREDENTIAL_TYPE ...) and fail fast on ambiguity.

Phase 2 - Protect every inbound surface. MCP servers: AuthProvider wrapping the server, with audience set to the server's Resource identifier. A2A agents: agent card at /.well-known/agent-card.json, RFC 9728 protected-resource metadata, KeycardAuthBackend(require_authentication=True) on /a2a/jsonrpc, audience = the agent's identity URL, KeycardServerCallContextBuilder so executors read keycard_user(context). Unauthenticated calls must get 401 with WWW-Authenticate resource_metadata.

Phase 3 - Delegation. Outbound agent-to-agent calls go through DelegationClient (discover -> token exchange with subject_token = the caller's verified token -> SendMessage with A2A-Version 1.0). Calls to third-party APIs use @grant / AccessContext (always check has_errors()) or keycardai-oauth TokenExchangeRequest with resource = the API. Never forward an inbound token to another service. Handle access_denied (policy) and insufficient_authorization (user must authorize) distinctly, and surface a sign-in link for the latter.

Phase 4 - No-user paths. Background jobs use client credentials (as themselves). Only where a job truly must act as a specific absent user, use impersonation: confidential client, consent implicit, an explicit Cedar permit on context.impersonate == true, and the user must have delegated before. Never take the user identifier from unverified request data.

Phase 5 - Framework hooks. If agents use LangChain/LangGraph, Pydantic AI or Temporal, mint tokens per tool call / per execution with the Keycard integration (e.g. KeycardGrantMiddleware with Access.on_behalf_of / as_self) so the model never sees a credential.

Phase 6 - Policy as code. Write Cedar policies in policies/*.cedar: default deny (replace the managed default-user-grants), group-based access per agent, app-to-app delegation only when context.on_behalf, per-tool rules for MCP via Keycard::Action::"mcp::tools/call::TOOL" if a gateway is used, and forbid rules for dangerous tools. Add a test matrix (principal, action, resource, context -> expected decision) and tell me how to run it in Console > Policies > Testing; if the Keycard Terraform provider fits our stack, manage policy sets with it.

Phase 7 - Containment and coding agents. For untrusted or sandboxed agents, design the egress-proxy sidecar allow list (exact hosts, ports, path prefixes matching Resources). For developers' coding agents, add keycard.toml mapping env vars to resources and document keycard run.

Phase 8 - Audit and revocation. Log Keycard sid and jti with every outbound call. Document how to trace one user request across all hops in Console > Audit Log & Sessions, how to export to S3 (OCSF) / our SIEM, and the revocation runbook (revoke grant, disable user, revoke at third-party provider, rotate vaulted secrets; held tokens live until exp).

Acceptance tests (automate what you can, list the rest as manual steps):
1. Every protected endpoint returns 401 without a token.
2. A token minted for agent A is rejected by agent B (audience).
3. User -> orchestrator -> worker -> API works and the audit log shows one sid across hops.
4. Removing the user from the required group gives access_denied on the next call without re-login.
5. Revoking the user's grant gives insufficient_authorization on the next exchange.
6. A forbidden tool is blocked before it reaches the MCP server.
7. grep finds no static API keys or long-lived tokens in the repo or images.

Deliverables: code changes, policies/, keycard.toml, .env.example without secrets, a README section with the data-flow diagram of every hop (who calls whom, which token, which audience, which policy), and the Console checklist.
```

Also saved as `PROMPT.md` in the code kit.

**Sources.** Keycard documentation: [How Keycard works](https://docs.keycard.ai/concepts.md), [Credential issuance](https://docs.keycard.ai/concepts/credentials.md), [Policies](https://docs.keycard.ai/concepts/policies.md), [Policy schema](https://docs.keycard.ai/reference/policy-schema.md), [Token claims](https://docs.keycard.ai/reference/token-claims.md), [Agent-to-agent SDK](https://docs.keycard.ai/sdk/agent-to-agent.md), [MCP SDK](https://docs.keycard.ai/sdk/mcp.md), [Gateway fine-grained authorization](https://docs.keycard.ai/admin/unified-access-gateway/fine-grained-authorization.md), [Egress proxy](https://docs.keycard.ai/reference/egress-proxy.md), [CLI](https://docs.keycard.ai/cli.md), [Revoke once](https://docs.keycard.ai/use-cases/revoke-once.md), [Audit log export](https://docs.keycard.ai/admin/audit-log-export.md). SDK source: [keycardai/python-sdk](https://github.com/keycardai/python-sdk), [keycardai/typescript-sdk](https://github.com/keycardai/typescript-sdk). Code here was checked against keycardai-a2a 0.5.1, keycardai-mcp 2.3.10, keycardai-oauth 0.37.1, keycardai-langchain 0.7.5. Token values and names in diagrams are sample data.