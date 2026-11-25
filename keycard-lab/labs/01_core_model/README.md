# Lab 01: core model (challenge, request, evaluate, credential, access)

**Proves:** a resource never trusts a caller without a token minted *for it*. The caller finds the zone on its own: 401 → `resource_metadata` (RFC 9728) → zone metadata → token → retry.

```bash
./mz up
.venv/bin/python labs/01_core_model/explore.py --user alice
```

**Expected:**
1. `HTTP 401`, with `WWW-Authenticate: Bearer ... resource_metadata="http://localhost:8000/.well-known/oauth-protected-resource/mcp"`.
2. Metadata showing `authorization_servers: ["http://localhost:9000/"]`.
3. The zone's token, authorize and JWKS endpoints.
4. A token with `aud = http://localhost:8000/mcp`, `sub_profile = user` and a `sid`.
5. `HTTP 200`.
6. The same token sent to the orchestrator gets `HTTP 401 ... Token verification failed`, because the audience is wrong.

**Try:** `--user carol`. The sign-in is refused (`access_denied`) because no policy permits her. Then run `./mz audit` and find the `deny` decision. Denials are logged even though no credential is issued.

**Vocabulary:** zone, users, applications, resources, providers, policies, credentials (see the field guide's glossary).
