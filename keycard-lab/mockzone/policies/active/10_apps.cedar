// What each APPLICATION (agent / server) may do. For delegated requests
// (an app acting for a user) Keycard requires BOTH the user and the app
// to be permitted, so privilege can only narrow at each hop.

@id("cli-signs-users-in")
permit (principal is Keycard::Application, action == Keycard::Action::"any", resource)
when {
  principal.identifier == "oncall-cli" && context.on_behalf == true &&
  ["http://localhost:8000/mcp", "http://localhost:8001", "http://localhost:8100/mcp", "http://localhost:8300"].contains(resource.identifier)
};

// MCP clients that self-register (DCR), e.g. Claude Code / MCP Inspector.
@id("public-mcp-clients-sign-in")
permit (principal is Keycard::Application, action == Keycard::Action::"any", resource)
when {
  principal.credential_type == "public" && context.on_behalf == true &&
  ["http://localhost:8000/mcp", "http://localhost:8100/mcp"].contains(resource.identifier)
};

@id("orchestrator-delegates-to-triage")
permit (principal is Keycard::Application, action == Keycard::Action::"any", resource)
when {
  principal.identifier == "incident-orchestrator" &&
  resource.identifier == "http://localhost:8002" &&
  context.on_behalf == true
};

@id("tools-call-github-for-user")
permit (principal is Keycard::Application, action == Keycard::Action::"any", resource)
when {
  ["triage-agent", "github-mcp", "oncall-langchain"].contains(principal.identifier) &&
  resource.identifier == "https://api.github.com" &&
  context.on_behalf == true
};

// Autonomous access (no user): the app acts as itself.
@id("jobs-act-as-themselves")
permit (principal is Keycard::Application, action == Keycard::Action::"any", resource)
when {
  ["nightly-digest", "oncall-langchain"].contains(principal.identifier) &&
  context.on_behalf == false && context.impersonate == false &&
  resource.identifier == "https://api.github.com"
};

@id("reports-writers")
permit (principal is Keycard::Application, action == Keycard::Action::"any", resource)
when {
  ["nightly-digest", "workload-agent"].contains(principal.identifier) &&
  context.on_behalf == false &&
  resource.identifier == "https://reports.internal.example"
};
