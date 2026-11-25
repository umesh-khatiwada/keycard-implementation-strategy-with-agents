# Lab 12: CLI and coding agents. REAL ACCOUNT ONLY

**Proves:** a developer's coding agent (Claude Code, scripts, CI) gets just-in-time, narrower-than-you credentials in one audited session, and nothing is stored in `.env`.

```bash
brew install keycardai/tap/keycard
keycard auth signin --zone <zone-id> --org <org>           # add --device on a headless box
cp labs/12_cli/keycard.toml ./keycard.toml                 # then set your zone id
keycard run -- sh -c 'test -n "$GH_TOKEN" && echo "GH_TOKEN is set"; gh api user --jq .login'   # never echo the token
keycard run claude                                         # Claude Code with KEYCARD_RUN=1 and KEYCARD_RUN_SESSION_ID set
keycard credential read https://api.github.com
keycard credential sync --mcp                              # add entries for every MCP server in the zone
keycard agent exec -- ./ci.sh                              # non-interactive variant
keycard plugin install claude
```

**Check:** `GH_TOKEN` exists only inside the `keycard run` process (`test -n "$GH_TOKEN" || echo unset` outside it prints `unset`). In Console > Audit Log & Sessions, every `gh`/`git` call is attributed to you *through* the coding agent.

Not covered by the mock or the acceptance suite.
