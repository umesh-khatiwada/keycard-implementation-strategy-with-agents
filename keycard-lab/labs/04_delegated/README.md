# Lab 04: delegated access (call GitHub as the signed-in user)

**Proves:** `@auth_provider.grant("https://api.github.com")` performs an RFC 8693 exchange before the tool body runs. The exchange uses `subject_token` = the caller's token and `resource` = GitHub, and the server authenticates as itself. Policy must permit **both** the app and the user, and GitHub is brokered only if the user connected it earlier. No GitHub token is ever stored on the server.

Code: the `recent_commits`, `list_incident_issues` and `open_incident_issue` tools in `../03_mcp_server/github_mcp.py`.

```bash
.venv/bin/python labs/03_mcp_server/mcp_client.py --user alice --tool list_incident_issues
.venv/bin/python labs/03_mcp_server/mcp_client.py --user bob --fresh --tool recent_commits
./mz grant bob https://api.github.com          # bob "connects GitHub"
.venv/bin/python labs/03_mcp_server/mcp_client.py --user bob --tool recent_commits
```

**Expected:**
- alice gets the issues.
- bob first gets an error with `code: insufficient_authorization`, because he never connected GitHub. This is not a policy denial.
- After `./mz grant`, bob gets the commits, read as `bob-gh`.

**Try:**
- Remove `"github-mcp"` from `tools-call-github-for-user` in `mockzone/policies/active/10_apps.cedar`. The next call fails with `access_denied` (the app is not permitted) with no restart. Put it back.
- In the tool, skip the `access_ctx.has_errors()` check. `AccessContext` is non-throwing by design, so you would end up calling GitHub with no token.
