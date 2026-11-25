# Lab 06: autonomous access (an agent acting as itself)

**Proves:** with no user present, the job uses **client credentials**. Only the application is evaluated by policy. The resulting token has `sub_profile=app`, and the audit shows the app with no person.

```bash
.venv/bin/python labs/06_autonomous/nightly_digest.py --mode as_self
.venv/bin/python labs/02_identity/identity_demo.py secret     # the same grant, for a Keycard-issued JWT resource
```

**Expected:**
- GitHub `/pulls` is listed while *acting as `nightly-digest-gh`* (a vaulted org credential, not Alice's).
- The reports API token shows `sub_profile: "app"`.

**Try:**
- Run `nightly_digest.py --resource http://localhost:8002`. You get `access_denied`, because no permit lets the job reach triage as itself.
- Note what you *cannot* do: client credentials never reach Alice's brokered GitHub. That needs lab 07.
