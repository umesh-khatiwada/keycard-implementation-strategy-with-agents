// Lab 09: what a NEW real zone ships with (managed default-zone-policies).
// Every authenticated user reaches every resource. Enable to see carol get in.
@id("default-user-grants")
permit (principal is Keycard::User, action, resource);
