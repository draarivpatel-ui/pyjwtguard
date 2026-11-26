"""pyjwtguard: zero-dependency hardened JWT and JWS verification.

Typical use::

    from pyjwtguard import HmacKey, sign_jwt, verify_jwt

    key = HmacKey.generate("HS256")
    token = sign_jwt({"sub": "user-1", "aud": "api", "exp": 2000000000}, key)
    claims = verify_jwt(token, key, algorithms=["HS256"], audience="api")
"""

from __future__ import annotations

from .asymmetric import (
    AlgorithmProvider,
    AlgorithmSigner,
    AlgorithmVerifier,
    AsymmetricSigner,
    AsymmetricVerifier,
)
from .crypto import (
    MINIMUM_ENTROPY_BITS,
    MINIMUM_SECRET_BYTES,
    SUPPORTED_HMAC_ALGORITHMS,
    HmacKey,
)
from .errors import ERROR_CODES, JwtGuardError
from .jwt import (
    DEFAULT_MAX_TOKEN_SIZE,
    MAX_NUMERIC_DATE,
    MIN_NUMERIC_DATE,
    TokenInspection,
    decode_unverified,
    inspect_header,
    inspect_token,
    sign_jwt,
    verify_jwt,
)

__version__ = "1.0.0"

__all__ = [
    "AlgorithmProvider",
    "AlgorithmSigner",
    "AlgorithmVerifier",
    "AsymmetricSigner",
    "AsymmetricVerifier",
    "DEFAULT_MAX_TOKEN_SIZE",
    "ERROR_CODES",
    "HmacKey",
    "JwtGuardError",
    "MAX_NUMERIC_DATE",
    "MINIMUM_ENTROPY_BITS",
    "MINIMUM_SECRET_BYTES",
    "MIN_NUMERIC_DATE",
    "SUPPORTED_HMAC_ALGORITHMS",
    "TokenInspection",
    "__version__",
    "decode_unverified",
    "inspect_header",
    "inspect_token",
    "sign_jwt",
    "verify_jwt",
]
