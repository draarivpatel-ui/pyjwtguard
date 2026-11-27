"""Token signing, verification, and structural inspection.

The verifier never trusts ``header.alg``. A caller supplied allowlist decides
which algorithms may run, the ``none`` family is rejected before anything else,
and every segment is decoded and parsed under strict rules. Signature checking
happens before claims are parsed, so unauthenticated JSON is never evaluated
against the claim policy.
"""

from __future__ import annotations

import json
import math
import time
import unicodedata
from collections.abc import Mapping as AbcMapping
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple, Union

from .asymmetric import AlgorithmSigner, AlgorithmVerifier
from .base64url import b64url_decode, b64url_encode
from .crypto import HMAC_SPECS, HmacKey, hmac_sign, hmac_verify
from .errors import (
    ALGORITHM_NONE,
    ALGORITHM_NOT_ALLOWED,
    ALGORITHM_UNSUPPORTED,
    AUDIENCE_MISMATCH,
    CLAIM_INVALID,
    CLAIM_MISSING,
    CLAIMS_INVALID,
    CONFIG_INVALID,
    CRIT_INVALID,
    CRIT_UNKNOWN,
    HEADER_FORBIDDEN,
    HEADER_INVALID,
    ISSUER_MISMATCH,
    JWT_ID_MISMATCH,
    KEY_CONFUSION,
    KEY_INVALID,
    KEY_NOT_FOUND,
    KID_INVALID,
    MALFORMED_TOKEN,
    SIGNATURE_INVALID,
    SIGNER_INVALID,
    SUBJECT_MISMATCH,
    TOKEN_EXPIRED,
    TOKEN_ISSUED_IN_FUTURE,
    TOKEN_NOT_YET_VALID,
    TOKEN_TOO_LARGE,
    TOKEN_TOO_OLD,
    TYPE_MISMATCH,
    VERIFIER_INVALID,
    JwtGuardError,
)
from .jsonparse import parse_json_object, validate_json_tree

DEFAULT_MAX_TOKEN_SIZE = 8192
MAX_KID_LENGTH = 256
MIN_NUMERIC_DATE = -62135596800
MAX_NUMERIC_DATE = 253402300799

REMOTE_HEADER_NAMES = ("jku", "x5u", "jwk", "x5c")
RESERVED_CRIT_NAMES = frozenset(
    {
        "alg",
        "crit",
        "kid",
        "typ",
        "cty",
        "jku",
        "jwk",
        "x5u",
        "x5c",
        "x5t",
        "x5t#s256",
    }
)

ClockLike = Union[Callable[[], float], int, float, None]
KeyResolver = Callable[[str], HmacKey]


@dataclass(frozen=True)
class TokenInspection:
    """Structural view of a token produced without signature verification."""

    header: Dict[str, Any]
    claims: Dict[str, Any]
    algorithm: str
    signature_bytes: int
    segment_lengths: Tuple[int, int, int]
    unencoded_payload: bool
    verified: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON serializable representation."""
        return {
            "header": dict(self.header),
            "claims": dict(self.claims),
            "algorithm": self.algorithm,
            "signature_bytes": self.signature_bytes,
            "unencoded_payload": self.unencoded_payload,
            "verified": False,
            "segments": {
                "header": self.segment_lengths[0],
                "payload": self.segment_lengths[1],
                "signature": self.segment_lengths[2],
            },
        }


def _config(message: str) -> JwtGuardError:
    return JwtGuardError(CONFIG_INVALID, message)


def _coerce_bool(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise _config("{} must be True or False".format(name))
    return value


def _coerce_algorithms(algorithms: Any) -> Tuple[str, ...]:
    if algorithms is None or isinstance(algorithms, (str, bytes, bytearray)):
        raise _config("algorithms must be a non-empty sequence of algorithm names")
    try:
        items = tuple(algorithms)
    except TypeError as exc:
        raise _config("algorithms must be a non-empty sequence of algorithm names") from exc
    if not items:
        raise _config("algorithms must not be empty")
    allowed: List[str] = []
    for item in items:
        if not isinstance(item, str) or not item:
            raise _config("every allowlisted algorithm must be a non-empty name")
        if item != item.strip():
            raise _config("allowlisted algorithm names must not contain outer whitespace")
        if item.lower() == "none":
            raise _config("the none algorithm can never be allowlisted")
        if item in allowed:
            raise _config("allowlisted algorithm names must be unique")
        allowed.append(item)
    return tuple(allowed)


def _coerce_leeway(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise _config("leeway must be a number of seconds")
    if isinstance(value, float) and not math.isfinite(value):
        raise _config("leeway must be finite")
    if value < 0:
        raise _config("leeway must not be negative")
    try:
        return float(value)
    except OverflowError as exc:
        raise _config("leeway is out of range") from exc


def _coerce_max_age(value: Any) -> Optional[float]:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise _config("max_age must be a number of seconds")
    if isinstance(value, float) and not math.isfinite(value):
        raise _config("max_age must be finite")
    if value <= 0:
        raise _config("max_age must be positive")
    try:
        return float(value)
    except OverflowError as exc:
        raise _config("max_age is out of range") from exc


def _current_time(now: ClockLike) -> float:
    if now is None:
        value: Any = time.time()
    elif callable(now):
        try:
            value = now()
        except Exception as exc:
            raise _config("the clock callable failed") from exc
    else:
        value = now
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise _config("the clock must be a number or a callable returning a number")
    if isinstance(value, float) and not math.isfinite(value):
        raise _config("the clock must return a finite number")
    try:
        result = float(value)
    except OverflowError as exc:
        raise _config("the clock value is out of range") from exc
    if not math.isfinite(result):
        raise _config("the clock must return a finite number")
    return result


def _coerce_max_token_size(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise _config("max_token_size must be an integer")
    if value < 1:
        raise _config("max_token_size must be at least 1")
    return value


def _coerce_understood(values: Any) -> frozenset:
    if values is None:
        return frozenset()
    if isinstance(values, (str, bytes, bytearray)):
        raise _config("understood_critical_headers must be a sequence of names")
    try:
        items = tuple(values)
    except TypeError as exc:
        raise _config("understood_critical_headers must be a sequence of names") from exc
    result = set()
    for item in items:
        if not isinstance(item, str) or not item:
            raise _config("critical header names must be non-empty strings")
        if item in result:
            raise _config("critical header names must be unique")
        result.add(item)
    return frozenset(result)


def _coerce_required_claims(values: Any) -> Tuple[str, ...]:
    if values is None:
        return ()
    if isinstance(values, (str, bytes, bytearray)):
        raise _config("required_claims must be a sequence of claim names")
    try:
        items = tuple(values)
    except TypeError as exc:
        raise _config("required_claims must be a sequence of claim names") from exc
    result: List[str] = []
    for item in items:
        if not isinstance(item, str) or not item:
            raise _config("required claim names must be non-empty strings")
        if item in result:
            raise _config("required claim names must be unique")
        result.append(item)
    return tuple(result)


def _coerce_providers(values: Any) -> Tuple[AlgorithmVerifier, ...]:
    if values is None:
        return ()
    if isinstance(values, (str, bytes, bytearray)):
        raise _config("providers must be a sequence of verifier objects")
    try:
        items = tuple(values)
    except TypeError as exc:
        raise _config("providers must be a sequence of verifier objects") from exc
    for item in items:
        if not callable(getattr(item, "supports", None)) or not callable(
            getattr(item, "verify", None)
        ):
            raise _config("every provider must implement supports() and verify()")
    return items


def _validate_provider_signer(provider: Any) -> AlgorithmSigner:
    if provider is None:
        raise _config("provider must not be None")
    if not callable(getattr(provider, "supports", None)) or not callable(
        getattr(provider, "sign", None)
    ):
        raise _config("provider must implement supports() and sign()")
    return provider


def _coerce_expected_string(value: Any, name: str) -> Optional[str]:
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise _config("{} must be a non-empty string".format(name))
    return value


def _coerce_expected_audience(value: Any) -> Optional[Tuple[str, ...]]:
    if value is None:
        return None
    if isinstance(value, str):
        if not value:
            raise _config("audience must not be empty")
        return (value,)
    if isinstance(value, (bytes, bytearray)):
        raise _config("audience must be a string or a sequence of strings")
    try:
        items = tuple(value)
    except TypeError as exc:
        raise _config("audience must be a string or a sequence of strings") from exc
    if not items:
        raise _config("audience must not be empty")
    result: List[str] = []
    for item in items:
        if not isinstance(item, str) or not item:
            raise _config("every expected audience must be a non-empty string")
        if item in result:
            raise _config("expected audiences must be unique")
        result.append(item)
    return tuple(result)


def _validate_kid(kid: Any) -> None:
    if not isinstance(kid, str):
        raise JwtGuardError(KID_INVALID, "kid must be a string")
    if not kid:
        raise JwtGuardError(KID_INVALID, "kid must not be empty")
    if len(kid) > MAX_KID_LENGTH:
        raise JwtGuardError(KID_INVALID, "kid is too long")
    if kid != kid.strip():
        raise JwtGuardError(KID_INVALID, "kid must not have outer whitespace")
    for char in kid:
        codepoint = ord(char)
        if codepoint < 0x20 or 0x7F <= codepoint <= 0x9F:
            raise JwtGuardError(KID_INVALID, "kid contains control characters")
        if unicodedata.category(char) in ("Cf", "Cs", "Co", "Cn"):
            raise JwtGuardError(KID_INVALID, "kid contains invisible formatting characters")
    if "/" in kid or "\\" in kid:
        raise JwtGuardError(KID_INVALID, "kid must not contain path separators")
    if ".." in kid:
        raise JwtGuardError(KID_INVALID, "kid must not contain path traversal")
    lowered = kid.lower()
    for marker in ("%2e", "%2f", "%5c", "%00", "%0a", "%0d", "%252e", "%252f", "%255c"):
        if marker in lowered:
            raise JwtGuardError(KID_INVALID, "kid must not contain encoded path traversal")
    for marker in ("'", '"', ";", "`"):
        if marker in kid:
            raise JwtGuardError(KID_INVALID, "kid contains SQL metacharacters")
    if "--" in kid or "/*" in kid or "*/" in kid:
        raise JwtGuardError(KID_INVALID, "kid contains comment sequences")


def _coerce_keyring(value: Any) -> Optional[Dict[str, HmacKey]]:
    if value is None:
        return None
    if not isinstance(value, AbcMapping):
        raise _config("keyring must be a mapping of kid values to HmacKey objects")
    if not value:
        raise _config("keyring must not be empty")
    result: Dict[str, HmacKey] = {}
    for kid, hmac_key in value.items():
        try:
            _validate_kid(kid)
        except JwtGuardError as exc:
            raise _config("keyring key identifiers must satisfy the kid policy") from exc
        if not isinstance(hmac_key, HmacKey):
            raise _config("keyring values must be HmacKey objects")
        result[kid] = hmac_key
    return result


def _coerce_key_resolver(value: Any) -> Optional[KeyResolver]:
    if value is None:
        return None
    if not callable(value):
        raise _config("key_resolver must be callable")
    return value


def _validate_crit(header: Dict[str, Any], understood: frozenset, allow_unencoded: bool) -> None:
    crit = header.get("crit")
    if not isinstance(crit, list) or not crit:
        raise JwtGuardError(CRIT_INVALID, "crit must be a non-empty JSON array")
    seen = set()
    unencoded = header.get("b64") is False
    for name in crit:
        if not isinstance(name, str) or not name:
            raise JwtGuardError(CRIT_INVALID, "crit entries must be non-empty strings")
        if name in seen:
            raise JwtGuardError(CRIT_INVALID, "crit entries must be unique")
        seen.add(name)
    for name in crit:
        if name == "b64":
            if not unencoded or not allow_unencoded:
                raise JwtGuardError(CRIT_INVALID, "crit must not list the registered b64 header")
            continue
        if name.lower() in RESERVED_CRIT_NAMES:
            raise JwtGuardError(CRIT_INVALID, "crit must not list a registered header")
        if name not in header:
            raise JwtGuardError(CRIT_INVALID, "crit names a header that is not present")
    for name in crit:
        if name != "b64" and name not in understood and name.lower() not in RESERVED_CRIT_NAMES:
            raise JwtGuardError(CRIT_UNKNOWN, "unsupported critical header")
    if unencoded and "b64" not in seen:
        raise JwtGuardError(CRIT_INVALID, "b64 false requires crit to contain b64")


def _validate_header_text(value: Any, name: str) -> None:
    if not isinstance(value, str) or not value:
        raise JwtGuardError(HEADER_INVALID, "header {} must be a non-empty string".format(name))
    for char in value:
        if ord(char) < 0x20 or ord(char) == 0x7F:
            raise JwtGuardError(HEADER_INVALID, "header {} contains control characters".format(name))


def _validate_remote_header_shapes(header: Dict[str, Any]) -> None:
    for name in ("jku", "x5u"):
        if name in header:
            _validate_header_text(header[name], name)
    if "jwk" in header and not isinstance(header["jwk"], dict):
        raise JwtGuardError(HEADER_INVALID, "header jwk must be a JSON object")
    if "x5c" in header:
        chain = header["x5c"]
        if not isinstance(chain, list) or not chain:
            raise JwtGuardError(HEADER_INVALID, "header x5c must be a non-empty array")
        for certificate in chain:
            if not isinstance(certificate, str) or not certificate:
                raise JwtGuardError(HEADER_INVALID, "header x5c entries must be non-empty strings")


def _validate_header(
    header: Dict[str, Any],
    *,
    allow_remote_headers: bool,
    understood_critical_headers: frozenset,
    allow_unencoded_payload: bool,
    expected_type: Optional[str] = None,
) -> Tuple[str, bool]:
    if "alg" not in header:
        raise JwtGuardError(HEADER_INVALID, "header is missing the alg value")
    algorithm = header["alg"]
    if not isinstance(algorithm, str) or not algorithm:
        raise JwtGuardError(HEADER_INVALID, "header alg must be a non-empty string")
    if algorithm.strip().lower() == "none":
        raise JwtGuardError(ALGORITHM_NONE, "the none algorithm is never accepted")
    for name in ("typ", "cty"):
        if name in header:
            _validate_header_text(header[name], name)
    if expected_type is not None:
        if "typ" not in header or header["typ"] != expected_type:
            raise JwtGuardError(TYPE_MISMATCH, "token type does not match")
    if "kid" in header:
        _validate_kid(header["kid"])
    if "b64" in header and not isinstance(header["b64"], bool):
        raise JwtGuardError(HEADER_INVALID, "header b64 must be a boolean")
    payload_is_encoded = header.get("b64", True)
    if payload_is_encoded is False and not allow_unencoded_payload:
        raise JwtGuardError(HEADER_INVALID, "unencoded JWS payloads require explicit opt in")
    if not allow_remote_headers:
        for name in REMOTE_HEADER_NAMES:
            if name in header:
                raise JwtGuardError(
                    HEADER_FORBIDDEN,
                    "header {} is not allowed by default".format(name),
                )
    _validate_remote_header_shapes(header)
    if "crit" in header:
        _validate_crit(header, understood_critical_headers, allow_unencoded_payload)
    elif payload_is_encoded is False:
        raise JwtGuardError(CRIT_INVALID, "b64 false requires crit to contain b64")
    return algorithm, payload_is_encoded


def _split_token(token: Any, max_token_size: int) -> Tuple[str, str, str]:
    if not isinstance(token, str):
        raise JwtGuardError(MALFORMED_TOKEN, "token must be text")
    if len(token) > max_token_size:
        raise JwtGuardError(TOKEN_TOO_LARGE, "token exceeds the configured size limit")
    try:
        encoded_size = len(token.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise JwtGuardError(MALFORMED_TOKEN, "token is not valid UTF-8") from exc
    if encoded_size == 0:
        raise JwtGuardError(MALFORMED_TOKEN, "token is empty")
    if encoded_size > max_token_size:
        raise JwtGuardError(TOKEN_TOO_LARGE, "token exceeds the configured size limit")
    parts = token.split(".")
    if len(parts) != 3:
        raise JwtGuardError(MALFORMED_TOKEN, "token must contain exactly three segments")
    if not parts[0] or not parts[1]:
        raise JwtGuardError(MALFORMED_TOKEN, "header and payload segments must not be empty")
    return parts[0], parts[1], parts[2]


def _serialize_json(value: Any, *, code: str, context: str, ensure_ascii: bool = False) -> bytes:
    try:
        text = json.dumps(
            value,
            ensure_ascii=ensure_ascii,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=False,
        )
    except (TypeError, ValueError, RecursionError) as exc:
        raise JwtGuardError(code, "{} cannot be serialized as JSON".format(context)) from exc
    try:
        return text.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise JwtGuardError(code, "{} is not valid Unicode for JSON".format(context)) from exc


def _validate_unencoded_payload_text(text: str) -> None:
    if not text:
        raise JwtGuardError(CLAIMS_INVALID, "unencoded payload must not be empty")
    for char in text:
        codepoint = ord(char)
        if char == "." or codepoint < 0x20 or codepoint > 0x7E:
            raise JwtGuardError(
                CLAIMS_INVALID,
                "unencoded compact payloads may contain printable ASCII except period",
            )


def _payload_bytes(payload_segment: str, payload_is_encoded: bool) -> bytes:
    if payload_is_encoded:
        return b64url_decode(payload_segment)
    try:
        text = payload_segment.encode("ascii").decode("ascii")
    except UnicodeError as exc:
        raise JwtGuardError(CLAIMS_INVALID, "unencoded payload must be ASCII") from exc
    _validate_unencoded_payload_text(text)
    return text.encode("ascii")


def _audience_values(value: Any) -> Tuple[str, ...]:
    if isinstance(value, str):
        if not value:
            raise JwtGuardError(CLAIM_INVALID, "aud must not be empty")
        return (value,)
    if isinstance(value, list) and value:
        for item in value:
            if not isinstance(item, str) or not item:
                raise JwtGuardError(
                    CLAIM_INVALID,
                    "aud must contain only non-empty strings",
                )
        if len(set(value)) != len(value):
            raise JwtGuardError(CLAIM_INVALID, "aud entries must be unique")
        return tuple(value)
    raise JwtGuardError(
        CLAIM_INVALID,
        "aud must be a string or a non-empty array of strings",
    )


def _numeric_date(claims: Dict[str, Any], name: str) -> Union[int, float]:
    value = claims[name]
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise JwtGuardError(CLAIM_INVALID, "{} must be a numeric date".format(name))
    if isinstance(value, float) and not math.isfinite(value):
        raise JwtGuardError(CLAIM_INVALID, "{} must be finite".format(name))
    if value < MIN_NUMERIC_DATE or value > MAX_NUMERIC_DATE:
        raise JwtGuardError(CLAIM_INVALID, "{} is outside the supported date range".format(name))
    return value


def _validate_claim_shapes(claims: Dict[str, Any]) -> None:
    for name in ("exp", "nbf", "iat"):
        if name in claims:
            _numeric_date(claims, name)
    if "iss" in claims:
        value = claims["iss"]
        if not isinstance(value, str) or not value:
            raise JwtGuardError(CLAIM_INVALID, "iss must be a non-empty string")
    if "aud" in claims:
        _audience_values(claims["aud"])
    if "sub" in claims:
        value = claims["sub"]
        if not isinstance(value, str) or not value:
            raise JwtGuardError(CLAIM_INVALID, "sub must be a non-empty string")
    if "jti" in claims:
        value = claims["jti"]
        if not isinstance(value, str) or not value:
            raise JwtGuardError(CLAIM_INVALID, "jti must be a non-empty string")


def _validate_claims(
    claims: Dict[str, Any],
    *,
    now: float,
    leeway: float,
    issuer: Optional[str],
    audience: Optional[Tuple[str, ...]],
    subject: Optional[str],
    jti: Optional[str],
    require_exp: bool,
    require_iat: bool,
    require_nbf: bool,
    required_claims: Tuple[str, ...],
    max_age: Optional[float],
) -> None:
    for name in required_claims:
        if name not in claims:
            raise JwtGuardError(CLAIM_MISSING, "{} claim is required".format(name))
        required_value = claims[name]
        if required_value is None or (
            isinstance(required_value, (str, list, dict)) and not required_value
        ):
            raise JwtGuardError(CLAIM_INVALID, "{} claim must not be null or empty".format(name))
    if require_exp and "exp" not in claims:
        raise JwtGuardError(CLAIM_MISSING, "exp claim is required")
    if require_iat and "iat" not in claims:
        raise JwtGuardError(CLAIM_MISSING, "iat claim is required")
    if require_nbf and "nbf" not in claims:
        raise JwtGuardError(CLAIM_MISSING, "nbf claim is required")
    _validate_claim_shapes(claims)
    if "exp" in claims:
        expiration = _numeric_date(claims, "exp")
        if now >= expiration + leeway:
            raise JwtGuardError(TOKEN_EXPIRED, "token has expired")
    if "nbf" in claims:
        not_before = _numeric_date(claims, "nbf")
        if now + leeway < not_before:
            raise JwtGuardError(TOKEN_NOT_YET_VALID, "token is not valid yet")
    issued_at: Optional[Union[int, float]] = None
    if "iat" in claims:
        issued_at = _numeric_date(claims, "iat")
        if now + leeway < issued_at:
            raise JwtGuardError(TOKEN_ISSUED_IN_FUTURE, "token was issued in the future")
    if max_age is not None:
        if issued_at is None:
            raise JwtGuardError(CLAIM_MISSING, "iat claim is required when max_age is used")
        if now - issued_at > max_age + leeway:
            raise JwtGuardError(TOKEN_TOO_OLD, "token exceeds the configured maximum age")
    if issuer is not None:
        if "iss" not in claims:
            raise JwtGuardError(CLAIM_MISSING, "iss claim is required")
        if claims["iss"] != issuer:
            raise JwtGuardError(ISSUER_MISMATCH, "issuer does not match")
    token_audience = _audience_values(claims["aud"]) if "aud" in claims else ()
    if audience is not None:
        if "aud" not in claims:
            raise JwtGuardError(CLAIM_MISSING, "aud claim is required")
        if not any(item in token_audience for item in audience):
            raise JwtGuardError(AUDIENCE_MISMATCH, "audience does not match")
    if subject is not None:
        if "sub" not in claims:
            raise JwtGuardError(CLAIM_MISSING, "sub claim is required")
        if claims["sub"] != subject:
            raise JwtGuardError(SUBJECT_MISMATCH, "subject does not match")
    if jti is not None:
        if "jti" not in claims:
            raise JwtGuardError(CLAIM_MISSING, "jti claim is required")
        if claims["jti"] != jti:
            raise JwtGuardError(JWT_ID_MISMATCH, "token identifier does not match")


def _provider_supports(provider: Any, algorithm: str, *, signing: bool) -> bool:
    try:
        result = provider.supports(algorithm)
    except JwtGuardError:
        raise
    except Exception as exc:
        code = SIGNER_INVALID if signing else VERIFIER_INVALID
        raise JwtGuardError(code, "provider failed while checking support") from exc
    if not isinstance(result, bool):
        code = SIGNER_INVALID if signing else VERIFIER_INVALID
        raise JwtGuardError(code, "provider supports() must return a boolean")
    return result


def _verify_asymmetric(
    algorithm: str,
    providers: Tuple[AlgorithmVerifier, ...],
    signing_input: bytes,
    signature: bytes,
    header: Dict[str, Any],
) -> None:
    supporting = []
    for provider in providers:
        if _provider_supports(provider, algorithm, signing=False):
            supporting.append(provider)
    if not supporting:
        raise JwtGuardError(
            ALGORITHM_UNSUPPORTED,
            "no provider supports {}".format(algorithm),
        )
    for provider in supporting:
        try:
            result = provider.verify(algorithm, signing_input, signature, dict(header))
        except JwtGuardError:
            raise
        except Exception as exc:
            raise JwtGuardError(VERIFIER_INVALID, "asymmetric verification failed") from exc
        if not isinstance(result, bool):
            raise JwtGuardError(VERIFIER_INVALID, "provider verify() must return a boolean")
        if result:
            return
    raise JwtGuardError(SIGNATURE_INVALID, "signature does not match")


def _select_hmac_key(
    key: Any,
    keyring: Optional[Dict[str, HmacKey]],
    key_resolver: Optional[KeyResolver],
    header: Dict[str, Any],
) -> Any:
    if key is not None:
        return key
    kid = header.get("kid")
    if kid is None:
        raise JwtGuardError(KID_INVALID, "key lookup requires a kid header")
    if keyring is not None:
        if kid not in keyring:
            raise JwtGuardError(KEY_NOT_FOUND, "kid is not present in the keyring")
        return keyring[kid]
    if key_resolver is not None:
        try:
            resolved = key_resolver(kid)
        except JwtGuardError:
            raise
        except (KeyError, LookupError) as exc:
            raise JwtGuardError(KEY_NOT_FOUND, "kid is not present in the keyring") from exc
        except Exception as exc:
            raise JwtGuardError(KEY_INVALID, "key resolver failed") from exc
        if not isinstance(resolved, HmacKey):
            raise JwtGuardError(KEY_INVALID, "key resolver must return an HmacKey")
        return resolved
    raise JwtGuardError(KEY_INVALID, "an HMAC secret is required")


def _count_key_sources(key: Any, keyring: Any, key_resolver: Any) -> int:
    return int(key is not None) + int(keyring is not None) + int(key_resolver is not None)


def sign_jwt(
    claims: Any,
    key: Any = None,
    *,
    algorithm: str = "HS256",
    headers: Any = None,
    provider: Optional[AlgorithmSigner] = None,
    understood_critical_headers: Any = (),
    allow_remote_headers: bool = False,
    allow_unencoded_payload: bool = False,
    allow_weak_keys: bool = False,
    max_token_size: int = DEFAULT_MAX_TOKEN_SIZE,
) -> str:
    """Create a compact JWS using HMAC or a pluggable external signer.

    ``key`` is the HMAC secret and is validated for type, minimum length,
    entropy, and asymmetric key confusion. When ``provider`` is given, ``key``
    must be omitted and the provider owns the private key.
    """
    if not isinstance(claims, AbcMapping):
        raise _config("claims must be a mapping")
    payload: Dict[str, Any] = {}
    for name, value in claims.items():
        if not isinstance(name, str) or not name:
            raise _config("claim names must be non-empty strings")
        payload[name] = value
    validate_json_tree(payload, invalid_code=CLAIM_INVALID, nonfinite_code=CLAIM_INVALID, context="claims")
    _validate_claim_shapes(payload)
    if not isinstance(algorithm, str) or not algorithm:
        raise _config("algorithm must be a non-empty string")
    if algorithm != algorithm.strip():
        raise _config("algorithm must not contain outer whitespace")
    if algorithm.lower() == "none":
        raise JwtGuardError(ALGORITHM_NONE, "the none algorithm can never be signed with")
    understood = _coerce_understood(understood_critical_headers)
    allow_remote = _coerce_bool(allow_remote_headers, "allow_remote_headers")
    allow_unencoded = _coerce_bool(allow_unencoded_payload, "allow_unencoded_payload")
    allow_weak = _coerce_bool(allow_weak_keys, "allow_weak_keys")
    limit = _coerce_max_token_size(max_token_size)
    header: Dict[str, Any] = {"alg": algorithm, "typ": "JWT"}
    if headers is not None:
        if not isinstance(headers, AbcMapping):
            raise _config("headers must be a mapping")
        for name, value in headers.items():
            if not isinstance(name, str) or not name:
                raise _config("header names must be non-empty strings")
            if name == "alg" and value != algorithm:
                raise _config("headers must not override alg")
            header[name] = value
    if allow_unencoded:
        if "b64" in header and header["b64"] is not False:
            raise _config("headers must not override b64 when unencoded_payload is enabled")
        header["b64"] = False
        existing_crit = header.get("crit")
        if existing_crit is None:
            header["crit"] = ["b64"]
        elif isinstance(existing_crit, list) and "b64" not in existing_crit:
            header["crit"] = list(existing_crit) + ["b64"]
        elif not isinstance(existing_crit, list):
            raise _config("crit must be a list when unencoded_payload is enabled")
    validate_json_tree(header, invalid_code=CONFIG_INVALID, nonfinite_code=CONFIG_INVALID, context="headers")
    _validate_header(
        header,
        allow_remote_headers=allow_remote,
        understood_critical_headers=understood,
        allow_unencoded_payload=allow_unencoded,
    )
    if provider is not None and key is not None:
        raise _config("pass either key or provider, not both")
    signer = None
    if provider is not None:
        signer = _validate_provider_signer(provider)
        if algorithm in HMAC_SPECS:
            raise _config("built-in HMAC algorithms require key material, not a provider")
        if not _provider_supports(signer, algorithm, signing=True):
            raise JwtGuardError(
                ALGORITHM_UNSUPPORTED,
                "provider does not support {}".format(algorithm),
            )
    elif key is None:
        raise JwtGuardError(KEY_INVALID, "an HMAC secret or provider is required")
    elif algorithm not in HMAC_SPECS:
        raise JwtGuardError(
            ALGORITHM_UNSUPPORTED,
            "no built-in signer supports {}".format(algorithm),
        )
    header_segment = b64url_encode(
        _serialize_json(header, code=CONFIG_INVALID, context="headers")
    )
    payload_bytes = _serialize_json(
        payload,
        code=CLAIM_INVALID,
        context="claims",
        ensure_ascii=allow_unencoded,
    )
    if allow_unencoded:
        try:
            payload_segment = payload_bytes.decode("ascii")
        except UnicodeDecodeError as exc:
            raise JwtGuardError(CLAIMS_INVALID, "unencoded payload must be ASCII") from exc
        _validate_unencoded_payload_text(payload_segment)
    else:
        payload_segment = b64url_encode(payload_bytes)
    signing_input = (header_segment + "." + payload_segment).encode("ascii")
    if signer is None:
        signature = hmac_sign(algorithm, key, signing_input, allow_weak_keys=allow_weak)
    else:
        try:
            produced = signer.sign(algorithm, signing_input, dict(header))
        except JwtGuardError:
            raise
        except Exception as exc:
            raise JwtGuardError(SIGNER_INVALID, "provider failed to produce a signature") from exc
        if not isinstance(produced, (bytes, bytearray, memoryview)):
            raise JwtGuardError(SIGNER_INVALID, "provider sign() must return bytes")
        signature = bytes(produced)
        if not signature:
            raise JwtGuardError(SIGNER_INVALID, "provider returned an empty signature")
    token = signing_input.decode("ascii") + "." + b64url_encode(signature)
    if len(token.encode("ascii")) > limit:
        raise JwtGuardError(TOKEN_TOO_LARGE, "generated token exceeds the configured size limit")
    return token


def verify_jwt(
    token: Any,
    key: Any = None,
    *,
    algorithms: Any = None,
    providers: Any = (),
    keyring: Any = None,
    key_resolver: Any = None,
    leeway: float = 0.0,
    now: ClockLike = None,
    issuer: Optional[str] = None,
    audience: Any = None,
    subject: Optional[str] = None,
    jti: Optional[str] = None,
    expected_type: Optional[str] = None,
    require_exp: bool = True,
    require_iat: bool = False,
    require_nbf: bool = False,
    required_claims: Any = (),
    max_age: Optional[float] = None,
    max_token_size: int = DEFAULT_MAX_TOKEN_SIZE,
    allow_remote_headers: bool = False,
    understood_critical_headers: Any = (),
    allow_unencoded_payload: bool = False,
    allow_weak_keys: bool = False,
) -> Dict[str, Any]:
    """Verify a compact JWS and return a copy of its claims.

    ``algorithms`` is a mandatory explicit allowlist. It is matched against the
    header exactly and case sensitively. Tokens using ``none`` in any casing are
    always rejected. HMAC keys must be bytes or text meeting the algorithm
    length and entropy floors unless ``allow_weak_keys`` is explicitly true.
    Asymmetric algorithms require a matching provider; this package has no
    asymmetric runtime dependency.
    """
    allowed = _coerce_algorithms(algorithms)
    skew = _coerce_leeway(leeway)
    maximum_age = _coerce_max_age(max_age)
    current_time = _current_time(now)
    expected_issuer = _coerce_expected_string(issuer, "issuer")
    expected_audience = _coerce_expected_audience(audience)
    expected_subject = _coerce_expected_string(subject, "subject")
    expected_jti = _coerce_expected_string(jti, "jti")
    expected_typ = _coerce_expected_string(expected_type, "expected_type")
    required = _coerce_required_claims(required_claims)
    limit = _coerce_max_token_size(max_token_size)
    allow_remote = _coerce_bool(allow_remote_headers, "allow_remote_headers")
    allow_unencoded = _coerce_bool(allow_unencoded_payload, "allow_unencoded_payload")
    allow_weak = _coerce_bool(allow_weak_keys, "allow_weak_keys")
    require_exp_flag = _coerce_bool(require_exp, "require_exp")
    require_iat_flag = _coerce_bool(require_iat, "require_iat")
    require_nbf_flag = _coerce_bool(require_nbf, "require_nbf")
    understood = _coerce_understood(understood_critical_headers)
    verifier_providers = _coerce_providers(providers)
    ring = _coerce_keyring(keyring)
    resolver = _coerce_key_resolver(key_resolver)
    if _count_key_sources(key, ring, resolver) > 1:
        raise _config("pass only one of key, keyring, or key_resolver")

    header_segment, payload_segment, signature_segment = _split_token(token, limit)
    header = parse_json_object(
        b64url_decode(header_segment),
        code=HEADER_INVALID,
        context="JWT header",
    )
    algorithm, payload_is_encoded = _validate_header(
        header,
        allow_remote_headers=allow_remote,
        understood_critical_headers=understood,
        allow_unencoded_payload=allow_unencoded,
        expected_type=expected_typ,
    )
    if algorithm not in allowed:
        raise JwtGuardError(
            ALGORITHM_NOT_ALLOWED,
            "header algorithm is not in the allowlist",
        )
    if not signature_segment:
        raise JwtGuardError(SIGNATURE_INVALID, "signature segment is empty")
    signature = b64url_decode(signature_segment)
    payload_bytes = _payload_bytes(payload_segment, payload_is_encoded)
    signing_input = (header_segment + "." + payload_segment).encode("ascii")
    if algorithm in HMAC_SPECS:
        if _count_key_sources(key, ring, resolver) == 0:
            raise JwtGuardError(KEY_INVALID, "an HMAC secret is required")
        selected_key = _select_hmac_key(key, ring, resolver, header)
        hmac_verify(
            algorithm,
            selected_key,
            signing_input,
            signature,
            allow_weak_keys=allow_weak,
        )
    else:
        if _count_key_sources(key, ring, resolver) != 0:
            raise _config("key, keyring, and key_resolver are only used for HMAC algorithms")
        _verify_asymmetric(algorithm, verifier_providers, signing_input, signature, header)
    claims = parse_json_object(
        payload_bytes,
        code=CLAIMS_INVALID,
        context="JWT claims",
    )
    _validate_claims(
        claims,
        now=current_time,
        leeway=skew,
        issuer=expected_issuer,
        audience=expected_audience,
        subject=expected_subject,
        jti=expected_jti,
        require_exp=require_exp_flag,
        require_iat=require_iat_flag,
        require_nbf=require_nbf_flag,
        required_claims=required,
        max_age=maximum_age,
    )
    return dict(claims)


def decode_unverified(
    token: Any,
    *,
    max_token_size: int = DEFAULT_MAX_TOKEN_SIZE,
    allow_remote_headers: bool = False,
    understood_critical_headers: Any = (),
    allow_unencoded_payload: bool = False,
) -> TokenInspection:
    """Decode a token without checking its signature or claims.

    Structural rules still apply: canonical base64url, no duplicate JSON keys,
    no non-finite numbers, and both segments must be JSON objects. The result is
    attacker controlled and must never be used for authorization.
    """
    limit = _coerce_max_token_size(max_token_size)
    allow_remote = _coerce_bool(allow_remote_headers, "allow_remote_headers")
    allow_unencoded = _coerce_bool(allow_unencoded_payload, "allow_unencoded_payload")
    understood = _coerce_understood(understood_critical_headers)
    header_segment, payload_segment, signature_segment = _split_token(token, limit)
    header = parse_json_object(
        b64url_decode(header_segment),
        code=HEADER_INVALID,
        context="JWT header",
    )
    algorithm, payload_is_encoded = _validate_header(
        header,
        allow_remote_headers=allow_remote,
        understood_critical_headers=understood,
        allow_unencoded_payload=allow_unencoded,
    )
    claims = parse_json_object(
        _payload_bytes(payload_segment, payload_is_encoded),
        code=CLAIMS_INVALID,
        context="JWT claims",
    )
    signature = b64url_decode(signature_segment)
    return TokenInspection(
        header=header,
        claims=claims,
        algorithm=algorithm,
        signature_bytes=len(signature),
        segment_lengths=(
            len(header_segment),
            len(payload_segment),
            len(signature_segment),
        ),
        unencoded_payload=not payload_is_encoded,
    )


def inspect_token(
    token: Any,
    *,
    max_token_size: int = DEFAULT_MAX_TOKEN_SIZE,
    allow_remote_headers: bool = False,
    understood_critical_headers: Any = (),
    allow_unencoded_payload: bool = False,
) -> TokenInspection:
    """Alias for :func:`decode_unverified` used by the inspection CLI."""
    return decode_unverified(
        token,
        max_token_size=max_token_size,
        allow_remote_headers=allow_remote_headers,
        understood_critical_headers=understood_critical_headers,
        allow_unencoded_payload=allow_unencoded_payload,
    )


def inspect_header(
    token: Any,
    *,
    max_token_size: int = DEFAULT_MAX_TOKEN_SIZE,
    allow_remote_headers: bool = False,
    understood_critical_headers: Any = (),
    allow_unencoded_payload: bool = False,
) -> Dict[str, Any]:
    """Return a structurally valid header after applying header policy.

    No signature is checked, so treat the output as untrusted diagnostic data.
    """
    limit = _coerce_max_token_size(max_token_size)
    allow_remote = _coerce_bool(allow_remote_headers, "allow_remote_headers")
    allow_unencoded = _coerce_bool(allow_unencoded_payload, "allow_unencoded_payload")
    understood = _coerce_understood(understood_critical_headers)
    header_segment, _, _ = _split_token(token, limit)
    header = parse_json_object(
        b64url_decode(header_segment),
        code=HEADER_INVALID,
        context="JWT header",
    )
    _validate_header(
        header,
        allow_remote_headers=allow_remote,
        understood_critical_headers=understood,
        allow_unencoded_payload=allow_unencoded,
    )
    return header


__all__ = [
    "DEFAULT_MAX_TOKEN_SIZE",
    "MAX_KID_LENGTH",
    "MAX_NUMERIC_DATE",
    "MIN_NUMERIC_DATE",
    "REMOTE_HEADER_NAMES",
    "ClockLike",
    "KeyResolver",
    "TokenInspection",
    "decode_unverified",
    "inspect_header",
    "inspect_token",
    "sign_jwt",
    "verify_jwt",
]
