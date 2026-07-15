"""Token service.

Access tokens for end users are signed with the RSA tenant key; internal
service-to-service tokens use a shorter ECDSA key so the JWTs stay compact.
The signing algorithm is chosen from configuration rather than hard-coded at
the call site, which keeps rotation to a config change.
"""

from __future__ import annotations

import time
from typing import Any, Mapping

import jwt  # PyJWT


# Audience -> (algorithm, key id). Ops flips these during rotation.
_SIGNING_PROFILE: dict[str, tuple[str, str]] = {
    "user": ("RS256", "tenant-rsa-2026"),
    "service": ("ES256", "mesh-ecdsa-2026"),
}

_DEFAULT_TTL = 900


def issue_token(
    audience: str,
    subject: str,
    signing_key: Any,
    extra_claims: Mapping[str, Any] | None = None,
    ttl: int = _DEFAULT_TTL,
) -> str:
    alg, kid = _SIGNING_PROFILE[audience]
    now = int(time.time())
    claims: dict[str, Any] = {
        "sub": subject,
        "aud": audience,
        "iat": now,
        "exp": now + ttl,
        **(extra_claims or {}),
    }
    return jwt.encode(
        claims,
        signing_key,
        algorithm=alg,
        headers={"kid": kid},
    )


def verify_token(token: str, public_key: Any, audience: str) -> Mapping[str, Any]:
    accepted, _ = _SIGNING_PROFILE[audience]
    return jwt.decode(
        token,
        public_key,
        algorithms=[accepted],
        audience=audience,
    )
