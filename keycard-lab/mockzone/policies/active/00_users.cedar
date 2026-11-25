// Who (people) may reach what. Group membership is resolved at evaluation
// time, so removing someone from a group applies on their NEXT request.
// Note: there is NO default-user-grants here, so anything not permitted is denied.

@id("oncall-can-use-incident-stack")
permit (principal in Keycard::Group::"oncall-engineers", action == Keycard::Action::"any", resource)
when {
  [ "http://localhost:8000/mcp",      // GitHub MCP server
    "http://localhost:8001",          // orchestrator agent
    "http://localhost:8002",          // triage agent
    "http://localhost:8100/mcp",      // mini gateway
    "http://localhost:8300",          // LangChain agent
    "https://api.github.com"
  ].contains(resource.identifier)
};
