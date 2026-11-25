// Lab 07: lets the nightly digest act AS an absent user for GitHub.
// Enable with:  ./mz policy enable 90_digest-may-impersonate
@id("digest-may-impersonate-for-github")
permit (principal is Keycard::Application, action == Keycard::Action::"any", resource)
when {
  context.impersonate == true &&
  principal.identifier == "nightly-digest" &&
  resource.identifier == "https://api.github.com"
};
