# Lab 05: agent-to-agent delegation (A2A)

**Proves:** each agent accepts only tokens whose `aud` is its own URL. The orchestrator never forwards Alice's token. It **exchanges** it, getting the same subject and the same `sid` with a new audience, and policy is checked again at each hop, so privilege can only narrow.

```
alice --#1 aud=:8001--> orchestrator --exchange--> #2 aud=:8002 --> triage --exchange--> GitHub (as alice)
```

```bash
.venv/bin/python labs/05_a2a/ask.py --user alice "checkout is throwing 500s"
./mz logs orchestrator; ./mz logs triage
./mz audit <sid printed in token #1>
```

**Expected:** `[orchestrator] sub=alice via app=oncall-cli sid=s-…` and `[triage] sub=alice via app=incident-orchestrator sid=<same>`, followed by the open incidents. The audit for that `sid` shows three `credential_issued` events: `oncall-cli`, `incident-orchestrator` and `triage-agent`.

**Break it:**
- `ask.py --user alice --to http://localhost:8002`: Alice's orchestrator token sent straight to triage gets **401** (wrong audience).
- `LAB_FORWARD_INBOUND_TOKEN=1 .venv/bin/python labs/05_a2a/orchestrator_agent.py` (after `./mz down`, start the others by hand): the orchestrator forwards token #1 instead of exchanging it, and triage rejects it.
- `ask.py --user bob`: works, because bob is in `oncall-engineers`. The final GitHub step then reports `insufficient_authorization`.
- `ask.py --no-token`: 401.
- (mock zone) the zone also refuses to *exchange* a token that wasn't minted for the requesting app, for example the triage agent trying to exchange Alice's orchestrator token (#1). The acceptance suite checks this, and `./mz audit` shows `exchange_rejected`.

Code: `orchestrator_agent.py` (`DelegationClient.invoke_service(..., subject_token=caller.access_token)`), `triage_agent.py` (`keycard_user(context)` + `exchange_token`), `../../common/a2a_app.py` (`KeycardAuthBackend(require_authentication=True)`, agent card, RFC 9728).
