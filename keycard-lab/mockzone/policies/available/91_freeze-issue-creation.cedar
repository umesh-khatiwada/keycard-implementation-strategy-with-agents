// Lab 10 kill switch: a forbid beats every permit, effective on the next call.
// Enable with:  ./mz policy enable 91_freeze-issue-creation
@id("freeze-issue-creation")
forbid (principal, action == Keycard::Action::"mcp::tools/call::open_incident_issue", resource);
