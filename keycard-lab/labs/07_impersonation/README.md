# Lab 07: impersonation (acting for an absent user)

**Proves:** all four preconditions must hold:
1. a confidential client
2. consent = `implicit`
3. a permit on `context.impersonate == true`, plus the user being permitted
4. prior user delegation for the resource.

Code: `../06_autonomous/nightly_digest.py --mode impersonate` (`Client.impersonate(user_identifier=..., resource=...)`).

```bash
./mz reset
.venv/bin/python labs/06_autonomous/nightly_digest.py --mode impersonate                       # 1
./mz policy enable 90_digest-may-impersonate
.venv/bin/python labs/06_autonomous/nightly_digest.py --mode impersonate                       # 2
.venv/bin/python labs/06_autonomous/nightly_digest.py --mode impersonate --user bob@example.com # 3
./mz policy disable 90_digest-may-impersonate
```

**Expected:**
1. `REFUSED: access_denied`. Default policies never allow impersonation.
2. GitHub *acting as alice-gh*.
3. `REFUSED: insufficient_authorization`. Bob never delegated GitHub.

**Try:**
- Set `"consent": "explicit"` for `nightly-digest` in `mockzone/zone.json` and run `./mz restart`. Impersonation is now refused even with the policy enabled.
- `python -m common.login --resource http://localhost:8001 --user alice`, then try impersonating with the public `oncall-cli`. Public clients may only use authorization code + PKCE, so the zone refuses.
- Lab 11's egress proxy uses the same grant, and `30_sandbox.cedar` pins it to a single user.

**Pitfall:** in MCP, `grant(..., user_identifier=...)` resolves the user per call. Take the identifier only from verified auth state or trusted job config, **never** from tool arguments a model can fill.
