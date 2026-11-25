# Lab 09: Cedar policies as code

**Proves:** default deny, any `forbid` beats every `permit`, delegated requests need user **and** app, group membership is evaluated at decision time, and a fresh zone's `default-user-grants` permits everything.

```bash
.venv/bin/python labs/09_policies/policy_matrix.py                                   # 16/16 expected
.venv/bin/python labs/09_policies/policy_matrix.py --with 92_default-user-grants     # watch rows flip
.venv/bin/python labs/09_policies/policy_matrix.py --with 91_freeze-issue-creation
.venv/bin/python labs/09_policies/policy_matrix.py --remove-from-group bob oncall-engineers
```

This runs offline with the real Cedar engine (`cedarpy`), against `mockzone/policies/active/*.cedar`. Each row prints which `@id` matched.

**Live:** `./mz policy enable 92_default-user-grants`, then `python -m common.login --resource http://localhost:8001 --user carol`. Carol gets in. Disable the policy again.

**Exercise:** write a policy so that **bob** may call `open_incident_issue` only when `context.scopes` contains `"incident:write"`. Add a matrix row first (test-first), watch it fail, then write the policy.

Policy files: `00_users.cedar` (people), `10_apps.cedar` (apps and delegation), `20_gateway_tools.cedar` (per tool), `30_sandbox.cedar`. Schema names follow Keycard's policy-schema reference: `Keycard::User/Group/Application/Resource`, `context.on_behalf/impersonate/subject/scopes`. With a real zone: Console > Policies > Testing, or the Keycard Terraform provider.
