// Per-tool rules enforced by the gateway (lab 10). Tool names are the bare
// upstream names; resource.identifier is the UPSTREAM MCP server URL.

@id("gateway-acts-for-users-upstream")
permit (principal is Keycard::Application, action, resource)
when {
  principal.identifier == "mcp-gateway" && context.on_behalf == true &&
  resource.identifier == "http://localhost:8000/mcp"
};

@id("oncall-may-list-tools")
permit (principal in Keycard::Group::"oncall-engineers", action in Keycard::Action::"MCPProtocol", resource)
when { resource.identifier == "http://localhost:8000/mcp" };

@id("oncall-read-tools")
permit (
  principal in Keycard::Group::"oncall-engineers",
  action in [Keycard::Action::"mcp::tools/call::ping",
             Keycard::Action::"mcp::tools/call::whoami",
             Keycard::Action::"mcp::tools/call::recent_commits",
             Keycard::Action::"mcp::tools/call::list_incident_issues"],
  resource
) when { resource.identifier == "http://localhost:8000/mcp" };

@id("open-issue-commanders-only")
permit (
  principal in Keycard::Group::"incident-commanders",
  action == Keycard::Action::"mcp::tools/call::open_incident_issue",
  resource
) when { resource.identifier == "http://localhost:8000/mcp" };
