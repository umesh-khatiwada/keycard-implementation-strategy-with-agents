# Keycard hands-on lab

Runnable examples for every feature in the *Keycard Field Guide*. There are 13 labs, one per feature. Each lab has code you can run, the output you should see, and things to try that break it on purpose.

All the code uses the **real Keycard SDKs** (`keycardai-mcp`, `keycardai-a2a`, `keycardai-oauth`, `keycardai-langchain`). It can run against:

| Target | When | How |
|---|---|---|
| **Local mock zone** (default) | No Keycard account, or you want to break things safely | Nothing to configure |
| **Your real Keycard zone** | You have a zone and want to see the Console, audit log and real IdP | Set `KEYCARD_ZONE_URL` and client ids in `.env` (see [Real zone](#running-against-a-real-keycard-zone)) |

> **The mock zone is not Keycard.** `mockzone/server.py` is a local simulator. It issues RS256 JWTs, runs PKCE, client credentials, RFC 8693 exchange and impersonation, evaluates Cedar policies with the real Cedar engine, brokers a fake GitHub, and keeps an audit log. It copies the behaviour described in Keycard's docs and the field guide. See [What the mock proves and what it doesn't](#what-the-mock-proves-and-what-it-doesnt).

## Setup (2 minutes)

```bash
cd keycard-lab
uv venv .venv -p 3.12 && uv pip install --python .venv/bin/python -r requirements.txt
./mz up          # mock zone :9000, MCP server :8000, orchestrator :8001, triage :8002, gateway :8100, egress proxy :8200
tests/run.sh     # optional: 20 automated checks, starts and stops its own services
```

`./mz` is the control panel for the mock zone. Use it to change groups, revoke grants, toggle policies and read the audit log. Run `./mz` with no arguments for help, and `./mz reset` to start again from a clean state. `./mz` and `tests/run.sh` always use the mock and ignore `.env`. Linux, or macOS with bash.

## The cast

| Who | Kind | Notes |
|---|---|---|
| alice | user | groups `oncall-engineers`, `incident-commanders`; has connected GitHub |
| bob | user | `oncall-engineers`; has **not** connected GitHub |
| carol | user | no groups, so default deny |
| `oncall-cli` | public app | signs people in (PKCE) |
| `github-mcp` | app + resource `http://localhost:8000/mcp` | MCP server with `@grant` GitHub tools |
| `incident-orchestrator` → `triage-agent` | apps + resources `:8001`, `:8002` | A2A chain |
| `nightly-digest` | app (consent implicit) | background job: as itself, or impersonating |
| `oncall-langchain` | app + resource `:8300` | LangChain agent |
| `mcp-gateway`, `egress-proxy`, `workload-agent` | apps | gateway, sandbox proxy, workload identity |
| `https://api.github.com` | brokered resource | fake GitHub at `http://localhost:9000/github` |

Policies live in `mockzone/policies/active/*.cedar` and are re-read on every request. Optional policies are in `available/` and are switched on with `./mz policy enable <name>`.

## Labs

| # | Feature (guide section) | Run | What you will see |
|---|---|---|---|
| [01](labs/01_core_model) | Core model: challenge, request, evaluate, credential, access | `python labs/01_core_model/explore.py` | 401 → RFC 9728 metadata → zone → token → 200, then a wrong-audience 401 |
| [02](labs/02_identity) | Agent identity without stored secrets | `python labs/02_identity/identity_demo.py workload` (and `... ambiguous`) | An app token from a platform OIDC token with no secret; separately, the credential-ambiguity error |
| [03](labs/03_mcp_server) | Protect an MCP server | `python labs/03_mcp_server/mcp_client.py --user alice` | `AuthProvider`: 401 challenge, PKCE, `whoami` |
| [04](labs/04_delegated) | Delegated access (`@grant`) | `... mcp_client.py --user alice --tool list_incident_issues` | GitHub called **as alice**; bob gets `insufficient_authorization` |
| [05](labs/05_a2a) | Agent-to-agent delegation | `python labs/05_a2a/ask.py --user alice` | Three hops, one `sid`; a forwarded token is rejected |
| [06](labs/06_autonomous) | Autonomous (client credentials) | `python labs/06_autonomous/nightly_digest.py` | `sub_profile=app`, no person involved |
| [07](labs/07_impersonation) | Impersonation | `... nightly_digest.py --mode impersonate` | `access_denied` → enable policy → works → bob `insufficient_authorization` |
| [08](labs/08_langchain) | Framework integration (LangChain) | `python labs/08_langchain/oncall_agent.py` | A token per tool call: `on_behalf_of` vs `as_self`; no LLM key needed |
| [09](labs/09_policies) | Cedar policies as code | `python labs/09_policies/policy_matrix.py` | Offline decision matrix; forbid beats permit; `default-user-grants` danger |
| [10](labs/10_gateway) | Gateway per-tool rules | `... mcp_client.py --url http://localhost:8100/mcp --user bob ...` | Tools filtered, -32603 over 403, kill switch on the next call |
| [11](labs/11_sandbox_proxy) | Sandbox egress proxy (*simulator; unreleased*) | `python labs/11_sandbox_proxy/sandboxed_agent.py` | Credential injected on the wire; deny reason codes |
| [12](labs/12_cli) | CLI and coding agents (*real account only*) | `keycard run -- …` | `keycard.toml` → just-in-time `GH_TOKEN` |
| [13](labs/13_audit_revoke) | Sessions, audit, revocation | `python labs/13_audit_revoke/scenario.py` | Revoke → `insufficient_authorization`; held token lives; group removal applies on the next issuance |

Run the commands from `keycard-lab/` with `.venv/bin/python`, or activate the venv first (`source .venv/bin/activate`).

### Suggested path (about 90 minutes)

1. **01 → 03 → 04**: the basics, with one server and one user.
2. **05**: the hop chain. Then run `./mz audit` and find your `sid`.
3. **06 → 07**: paths with no user present, and why impersonation is hard to get.
4. **09 → 10**: change a `.cedar` file and watch the next call change.
5. **13**: the incident timeline. Then take the Gatekeeper quiz in the field guide.

## Running against a real Keycard zone

1. In the Console, create these. The checklist matches Phase 0 of the field guide's prompt.
   - A **zone** with your IdP. Create the groups `oncall-engineers` and `incident-commanders`, and add yourself.
   - A **public Application** `oncall-cli` with redirect URI `http://localhost:8765/callback`.
   - A **confidential Application** for each of `github-mcp`, `incident-orchestrator`, `triage-agent`, `nightly-digest` (consent: implicit) and `oncall-langchain`. Copy their client ids and secrets.
   - **Resources** with these exact identifiers: `http://localhost:8000/mcp`, `http://localhost:8001`, `http://localhost:8002`, `http://localhost:8300`, `https://reports.internal.example` (used by lab 02 `secret` and lab 06; or point `REPORTS_RESOURCE` at any Resource the digest app may reach), and the **GitHub** catalog connector (`https://api.github.com`). Connect your own GitHub account.
   - **Policies**: activate a set **without** `default-user-grants`, built from `mockzone/policies/active/*.cedar`. Use `principal.identifier` values that match your Application identifiers.
2. `cp .env.example .env`. Set `KEYCARD_ZONE_URL`, `KEYCARD_ZONE_ID` and every `*_CLIENT_ID/SECRET`. Leave `GITHUB_API_BASE` unset, so it defaults to the real GitHub API, and set `DEMO_REPO` to a repo you can read.
3. Start the services one by one (`./mz up` also starts the mock zone, which you don't need here):
   `python labs/03_mcp_server/github_mcp.py`, `python labs/05_a2a/triage_agent.py`, `python labs/05_a2a/orchestrator_agent.py`.
4. Run the labs **without** `--user`. A browser opens and you sign in with your IdP.
5. Some features only work on the mock zone:
   - `mini_gateway.py`: use Keycard's Unified Access Gateway instead.
   - `identity_demo.py workload`: needs a real platform.
   - `./mz`: use the Console instead.
   - Lab 13's script runs on the mock only, because it needs two test users and simulated provider revocation. Its README lists the same steps to do by hand in the Console.

## What the mock proves and what it doesn't

**Real and verified here:** the SDK code paths:
- `AuthProvider`, `@grant` and `AccessContext`
- `KeycardAuthBackend`, the agent cards and `DelegationClient`
- `client_credentials_grant`, `exchange_token`, `impersonate` and the PKCE helpers
- `WorkloadIdentity`, `discover_credential` and `KeycardGrantMiddleware`
- token verification (signature, issuer, expiry, audience) on the resource side
- Cedar semantics (default deny, forbid wins, `in` group membership).

**Modelled on the Keycard docs and field guide, simulated by the mock:**
- that both user and app are evaluated on delegation
- `access_denied` vs `insufficient_authorization`
- impersonation preconditions (confidential client, implicit consent, policy, prior grant)
- group membership resolved at evaluation time
- revocation stopping only new issuance
- token claim names (`sub_profile`, `keycard_app_id`, `sid`, `jti`).

**The simulator's own choices, so don't rely on them:**
- the exact error bodies and the `authorization_url` field
- the strictness rules: exact `redirect_uri` matching, and refusing an exchange whose `subject_token` `aud` isn't the requesting app's own resource. These are good practice, but don't assume your zone enforces exactly these.
- the `act` claim shape
- audit event names and fields
- the substitute-user parsing
- the `/mock/*` endpoints
- the mini gateway and the egress proxy simulator (the real proxy is transparent and unreleased).

## Layout

```
mockzone/        server.py (simulator), zone.json (directory), policies/{active,available}/*.cedar
common/          settings.py (env), login.py (PKCE), tokens.py (claims, never prints tokens), a2a_app.py
labs/NN_*/       one folder per feature, each with a README
tests/           run.sh + acceptance.py (20 checks against the mock)
mz               mock zone control CLI
```
