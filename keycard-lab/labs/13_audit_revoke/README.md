# Lab 13: sessions, audit and revocation

**Proves:**
- Every hop of one request shares a `sid`, and each token has a unique `jti`.
- Revoking a grant stops the **next** issuance with `insufficient_authorization`, not `access_denied`.
- Already-held credentials live until `exp`, so you must also revoke at the provider.
- Removing someone from a group applies on their next issuance, without re-login.

```bash
./mz up
.venv/bin/python labs/13_audit_revoke/scenario.py
```

**Expected (abridged):**
```
=== 1. One user request, many hops, ONE session id ===
  credential_issued  app=oncall-cli            resource=http://localhost:8001  tok-…
  credential_issued  app=incident-orchestrator resource=http://localhost:8002  tok-…
  credential_issued  app=triage-agent          resource=https://api.github.com
=== 3. Admin revokes alice's GitHub grant ===
next exchange -> insufficient_authorization
held token still works until it expires: True
after revoking at the provider, held token works: False
=== 4. Bob is removed from oncall-engineers ===
delegation failed: ... access_denied ...
```

**By hand:** `./mz audit`, `./mz revoke alice https://api.github.com`, `./mz group remove oncall-engineers bob`, `./mz reset`.

**Real zone (by hand; the script is mock-only):** you need two test accounts, A (connected GitHub) and B (in the required group).
1. A runs `labs/05_a2a/ask.py`. In Console > Audit Log & Sessions, filter by the `sid` and see every hop.
2. Run `labs/03_mcp_server/mcp_client.py --tool recent_commits` as A. Revoke A's GitHub grant on the Resource's page. Run it again: you get `insufficient_authorization`.
3. Remove B from the group in your IdP or Keycard (SCIM). B's next `ask.py` (no re-login) gets `access_denied` at the orchestrator → triage exchange.
4. Revoke the app's authorization in GitHub settings too: Keycard revocation does not kill tokens GitHub has already issued.

Audit export: Export to S3 (OCSF v1.7 Parquet) for Splunk or Panther. Keycard-issued tokens default to 24h unless the Resource sets a shorter lifetime (`token_ttl` on `reports.internal.example` in `zone.json` shows this). Vaulted static secrets never expire on their own, so rotate them. 
