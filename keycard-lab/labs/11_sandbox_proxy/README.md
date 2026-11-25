# Lab 11: sandboxed agents (credentials added on the wire). SIMULATOR

> Keycard's egress proxy is **not yet released** (per the docs). This lab is a simulator of the documented behaviour, and the real configuration may differ.

**Proves:** an untrusted agent holds no credentials. The proxy checks an allow list (exact host, one port, longest path prefix). For credentialed endpoints it runs an impersonation exchange **for the sandbox's one user** and writes the credential into a header, overwriting whatever the agent sent. It writes one JSON audit line per decision.

```bash
.venv/bin/python labs/11_sandbox_proxy/sandboxed_agent.py
./mz logs egress
```

**Expected:** two GitHub calls succeed *as alice-gh* even though the agent sent `Bearer stolen-or-made-up`, and pypi is allowed with no credential. The others are denied: `no_matching_endpoint` (other org, exfiltration), `cleartext_not_forwarded` and `private_address_denied`.

**Try:** change `sandbox_user` in `egress.json` to `bob@example.com` and run `./mz restart`. You get `exchange_denied`, because `30_sandbox.cedar` pins the proxy to alice. That is why a workload token tied to one ServiceAccount beats a shared secret.

**Real deployment:** an init container installs iptables rules, so all outbound TCP and DNS goes to the sidecar and UDP/QUIC is dropped. The deny reason is returned in `X-Keycard-Deny-Reason`.
