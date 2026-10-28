"""Signed tokens of the chat assistant: JSON Web Tokens (RFC 7519) signed with HS256 by PyJWT.

Shared by the web Lambda (web/auth.py issues and checks session tokens, and issues tool tokens), the analysis and data
tool Lambdas (tools/common/caller.py checks tool tokens) and the admin CLI (`qsca smoke`, tests/e2e.py).

Two kinds of token, told apart by the audience claim; neither is accepted where the other is expected:
- session (aud "qsca:session"): the browser's sign-in, issued after IAM Identity Center SAML login. Short-lived
  (SESSION_SECONDS, default 1 hour), accepted only by the web Lambda, revoked on sign-out through its jti.
- tools (aud "qsca:tools"): issued by the web Lambda for one chat job (lifetime = the Runtime session's maximum
  lifetime) or one button click (5 minutes). Bound to the user and to one analysis ("analysis" claim, empty for the
  analysis picker), never sent to the browser, accepted only by the tool Lambdas.

The signing key is SHA-256 of the Secrets Manager secret SESSION_SECRET_ID (a random string of at least 32
characters; the stack generates 64).
"""

import hashlib
import time
import uuid

import jwt

ISSUER = "qsca:web"
SESSION_AUDIENCE = "qsca:session"
TOOLS_AUDIENCE = "qsca:tools"
ALGORITHM = "HS256"
MIN_SECRET_LENGTH = 32
MAX_TOKEN_LENGTH = 4096
LEEWAY_SECONDS = 30  # clock skew between the Lambdas that issue and check tokens
REQUIRED_CLAIMS = ("iss", "aud", "sub", "iat", "exp", "jti")


class InvalidToken(Exception):
    """The token is missing, malformed, forged, expired or meant for another audience."""

    def __init__(self, reason, expired=False):
        super().__init__(reason)
        self.expired = expired


def signing_key(secret_string):
    """The HMAC key derived from the session-key secret."""
    if not isinstance(secret_string, str) or len(secret_string) < MIN_SECRET_LENGTH:
        raise RuntimeError(f"session key secret must be at least {MIN_SECRET_LENGTH} characters")
    return hashlib.sha256(secret_string.encode("utf-8")).digest()


def mint(key, audience, subject, seconds, jti=None, **claims):
    """Return (token, claims) for `subject` (the user's email), valid for `seconds`."""
    if audience not in (SESSION_AUDIENCE, TOOLS_AUDIENCE):
        raise ValueError(f"unknown audience {audience!r}")
    if not isinstance(subject, str) or not subject:
        raise ValueError("subject is required")
    now = int(time.time())
    payload = {**claims, "iss": ISSUER, "aud": audience, "sub": subject, "iat": now, "exp": now + int(seconds),
               "jti": jti or uuid.uuid4().hex}
    return jwt.encode(payload, key, algorithm=ALGORITHM), payload


def verify(key, token, audience, required=()):
    """Return the claims of a valid token for `audience`, or raise InvalidToken.

    Only HS256 is accepted (no "none", no algorithm from the token header); issuer, audience, expiry and issued-at
    are checked by PyJWT, and every claim in REQUIRED_CLAIMS + `required` must be present."""
    if not isinstance(token, str) or not token or len(token) > MAX_TOKEN_LENGTH:
        raise InvalidToken("missing or oversized token")
    try:
        claims = jwt.decode(token, key, algorithms=[ALGORITHM], audience=audience, issuer=ISSUER,
                            leeway=LEEWAY_SECONDS, options={"require": [*REQUIRED_CLAIMS, *required]})
    except jwt.ExpiredSignatureError as error:
        raise InvalidToken("expired", expired=True) from error
    except jwt.InvalidTokenError as error:
        raise InvalidToken(type(error).__name__) from error
    if not isinstance(claims.get("sub"), str) or not claims["sub"]:
        raise InvalidToken("empty subject")
    return claims
