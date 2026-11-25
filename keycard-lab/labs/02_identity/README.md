# Lab 02: agent identity without stored secrets

**Proves:** every agent is its own Application, and it can prove who it is without a secret.

```bash
.venv/bin/python labs/02_identity/identity_demo.py secret     # ClientSecret: local development
.venv/bin/python labs/02_identity/identity_demo.py workload   # WorkloadIdentity(FileTokenSource): production pattern
.venv/bin/python labs/02_identity/identity_demo.py ambiguous  # discover_credential refuses to guess
```

**Expected:**
- `secret` and `workload` both print an **app token**: `sub_profile: "app"`, `sub == keycard_app_id`, no `sid`.
- `workload` first prints the *platform* token (`iss .../mock/platform`, `sub system:serviceaccount:agents:workload-agent`). That is what EKS Pod Identity or a Kubernetes projected service-account token gives your pod. The zone maps (issuer, subject) to the `workload-agent` Application (see `mockzone/zone.json`).
- `ambiguous` prints *"Ambiguous application credential configuration ... Set KEYCARD_APPLICATION_CREDENTIAL_TYPE"*, then shows that setting it resolves the ambiguity.

**In your services:**
```python
from keycardai.mcp.server.auth import AuthProvider, EKSWorkloadIdentity
AuthProvider(zone_id=..., audience=..., application_credential=EKSWorkloadIdentity())
# or let env decide: keycardai.oauth.server.credentials.discover_credential()
```

| Credential | Use when | SDK / env |
|---|---|---|
| Client secret | local development | `ClientSecret`, `KEYCARD_CLIENT_ID` + `KEYCARD_CLIENT_SECRET` |
| Private-key JWT | servers that can keep a key pair | `WebIdentity`, `KEYCARD_WEB_IDENTITY_KEY_STORAGE_DIR` (real zone only) |
| Workload identity | production on EKS, K8s, GCP, Azure, Vercel or Fly | `WorkloadIdentity` / `EKSWorkloadIdentity`, `KEYCARD_APPLICATION_CREDENTIAL_TYPE=workload_identity` |

*Mock note:* the mock zone plays the platform's OIDC issuer (`/mock/platform/token`). `workload` mode is mock-only.
