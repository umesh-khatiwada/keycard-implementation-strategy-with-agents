"""Small helpers: show token claims without ever printing the token itself."""
from __future__ import annotations

import json

import jwt


def claims(token: str) -> dict | None:
    try:
        return jwt.decode(token, options={"verify_signature": False})
    except jwt.PyJWTError:
        return None  # opaque (e.g. a brokered GitHub token)


def show(label: str, token: str, keys=("iss", "sub", "sub_profile", "keycard_app_id",
                                       "client_id", "aud", "scope", "sid", "jti", "act", "exp")) -> dict | None:
    c = claims(token)
    print(f"\n--- {label} ---")
    if c is None:
        print(f"  opaque credential ({token[:10]}…), not a JWT: brokered provider token")
        return None
    print(json.dumps({k: c[k] for k in keys if k in c}, indent=2))
    return c


def redact(token: str) -> str:
    return token[:12] + "…" if token else "<none>"
