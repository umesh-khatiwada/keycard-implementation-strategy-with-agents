// Egress proxy (lab 11) may impersonate ONLY the sandbox's own user, and only for GitHub.
@id("egress-proxy-impersonates-sandbox-user")
permit (principal is Keycard::Application, action == Keycard::Action::"any", resource)
when {
  principal.identifier == "egress-proxy" &&
  context.impersonate == true &&
  context has subject && context.subject == Keycard::User::"alice" &&
  resource.identifier == "https://api.github.com"
};
