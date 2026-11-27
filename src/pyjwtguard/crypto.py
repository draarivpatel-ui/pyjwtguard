"""HMAC signing primitives and key material policy.

Only HS256, HS384 and HS512 are implemented in the standard library. Each
algorithm enforces a minimum secret length equal to its digest output size and
a conservative Shannon entropy floor. Every secret is screened for PEM, JWK,
OpenSSH, and DER shaped asymmetric material before use. The latter check is a
core defense against key confusion: an API that passes an RSA public key to an
HMAC verifier must fail loudly instead of validating an attacker forged token.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import re
import secrets
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Mapping, Tuple

from .errors import (
    CONFIG_INVALID,
    KEY_CONFUSION,
    KEY_INVALID,
    SIGNATURE_INVALID,
    WEAK_KEY,
    JwtGuardError,
)

_PEM_MARKER = re.compile(
    rb"-----BEGIN [A-Z0-9][A-Z0-9 -]{0,79}-----",
    re.IGNORECASE,
)
_SSH_PUBLIC_KEY_TYPES = frozenset(
    (
        b"ssh-rsa",
        b"ssh-dss",
        b"rsa-sha2-256",
        b"rsa-sha2-512",
        b"ssh-ed25519",
        b"ecdsa-sha2-nistp256",
        b"ecdsa-sha2-nistp384",
        b"ecdsa-sha2-nistp521",
        b"sk-ssh-ed25519@openssh.com",
        b"sk-ecdsa-sha2-nistp256@openssh.com",
        b"ssh-rsa-cert-v01@openssh.com",
        b"rsa-sha2-256-cert-v01@openssh.com",
        b"rsa-sha2-512-cert-v01@openssh.com",
        b"ssh-dss-cert-v01@openssh.com",
        b"ssh-ed25519-cert-v01@openssh.com",
        b"ecdsa-sha2-nistp256-cert-v01@openssh.com",
        b"ecdsa-sha2-nistp384-cert-v01@openssh.com",
        b"ecdsa-sha2-nistp521-cert-v01@openssh.com",
        b"sk-ssh-ed25519-cert-v01@openssh.com",
        b"sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
    )
)
_SSH_TOKEN_EDGE_CHARS = b"'\"`;,[](){}"
_BASE64_KEY_CANDIDATE = re.compile(rb"[A-Za-z0-9+/_-]+={0,2}")
_HEX_KEY_CANDIDATE = re.compile(rb"[0-9a-fA-F]+")
_MAX_ENCODED_KEY_CANDIDATE_BYTES = 8192
_ASYMMETRIC_JWK_TYPES = (b'"rsa"', b'"ec"', b'"okp"')

_OID_RSA = bytes.fromhex("2a864886f70d010101")
_OID_RSA_PSS = bytes.fromhex("2a864886f70d01010a")
_OID_DSA = bytes.fromhex("2a8648ce380401")
_OID_EC_PUBLIC = bytes.fromhex("2a8648ce3d0201")
_OID_ED25519 = bytes.fromhex("2b6570")
_OID_ED448 = bytes.fromhex("2b6571")
_OID_X25519 = bytes.fromhex("2b6577")
_OID_X448 = bytes.fromhex("2b6578")
_KEY_OIDS = frozenset(
    (
        _OID_RSA,
        _OID_RSA_PSS,
        _OID_DSA,
        _OID_EC_PUBLIC,
        _OID_ED25519,
        _OID_ED448,
        _OID_X25519,
        _OID_X448,
    )
)


@dataclass(frozen=True)
class HmacSpec:
    """Digest, minimum length, and entropy floor for one HMAC algorithm."""

    digest: str
    minimum_key_bytes: int
    minimum_entropy_bits: int


HMAC_SPECS: Mapping[str, HmacSpec] = MappingProxyType(
    {
        "HS256": HmacSpec("sha256", 32, 128),
        "HS384": HmacSpec("sha384", 48, 192),
        "HS512": HmacSpec("sha512", 64, 256),
    }
)

SUPPORTED_HMAC_ALGORITHMS = tuple(HMAC_SPECS.keys())

MINIMUM_SECRET_BYTES = MappingProxyType(
    {name: spec.minimum_key_bytes for name, spec in HMAC_SPECS.items()}
)

MINIMUM_ENTROPY_BITS = MappingProxyType(
    {name: spec.minimum_entropy_bits for name, spec in HMAC_SPECS.items()}
)


def _read_tlv(data: bytes, offset: int, end: int) -> Tuple[int, int, int, int]:
    """Read one DER TLV and return tag, value start, value end, next offset."""
    if offset < 0 or end > len(data) or offset + 2 > end:
        raise ValueError("truncated DER value")
    tag = data[offset]
    length_byte = data[offset + 1]
    position = offset + 2
    if length_byte & 0x80:
        length_octets = length_byte & 0x7F
        if length_octets == 0 or length_octets > 4:
            raise ValueError("invalid DER length")
        if position + length_octets > end:
            raise ValueError("truncated DER length")
        if data[position] == 0:
            raise ValueError("non-minimal DER length")
        length = int.from_bytes(data[position : position + length_octets], "big")
        position += length_octets
    else:
        length = length_byte
    value_end = position + length
    if value_end > end:
        raise ValueError("DER value extends beyond input")
    return tag, position, value_end, value_end


def _sequence_children(data: bytes, start: int, end: int) -> Tuple[Tuple[int, int, int, int], ...]:
    children = []
    position = start
    while position < end:
        child = _read_tlv(data, position, end)
        children.append(child)
        position = child[3]
    if position != end:
        raise ValueError("DER sequence has trailing bytes")
    return tuple(children)


def _first_oid_in_sequence(data: bytes, child: Tuple[int, int, int, int]) -> bytes:
    tag, start, end, _ = child
    if tag != 0x30:
        raise ValueError("algorithm field is not a sequence")
    first = _read_tlv(data, start, end)
    if first[0] != 0x06:
        raise ValueError("algorithm field does not start with an OID")
    return data[first[1] : first[2]]


def _looks_like_spki_or_pkcs8(data: bytes) -> bool:
    if len(data) < 16 or data[0] != 0x30:
        return False
    try:
        outer = _read_tlv(data, 0, len(data))
        if outer[0] != 0x30 or outer[3] != len(data):
            return False
        children = _sequence_children(data, outer[1], outer[2])
        for index, child in enumerate(children[:2]):
            if child[0] != 0x30:
                continue
            oid = _first_oid_in_sequence(data, child)
            if oid not in _KEY_OIDS:
                continue
            later_tags = tuple(item[0] for item in children[index + 1 :])
            if 0x03 in later_tags or 0x04 in later_tags:
                return True
    except (IndexError, ValueError):
        return False
    return False


def _integer_content(data: bytes, child: Tuple[int, int, int, int]) -> bytes:
    return data[child[1] : child[2]].lstrip(b"\x00")


def _looks_like_pkcs1_rsa(data: bytes) -> bool:
    if len(data) < 80 or data[0] != 0x30:
        return False
    try:
        outer = _read_tlv(data, 0, len(data))
        if outer[0] != 0x30 or outer[3] != len(data):
            return False
        children = _sequence_children(data, outer[1], outer[2])
        if len(children) == 2:
            modulus_index, exponent_index = 0, 1
        elif len(children) in (8, 9):
            modulus_index, exponent_index = 1, 2
        else:
            return False
        if any(child[0] != 0x02 for child in children):
            return False
        modulus = _integer_content(data, children[modulus_index])
        exponent = _integer_content(data, children[exponent_index])
        return len(modulus) >= 64 and exponent in (b"\x03", b"\x01\x00\x01")
    except (IndexError, ValueError):
        return False


def _looks_like_sec1_ec_private_key(data: bytes) -> bool:
    if len(data) < 40 or data[0] != 0x30:
        return False
    try:
        outer = _read_tlv(data, 0, len(data))
        if outer[0] != 0x30 or outer[3] != len(data):
            return False
        children = _sequence_children(data, outer[1], outer[2])
        if len(children) < 2 or len(children) > 4:
            return False
        if children[0][0] != 0x02 or children[1][0] != 0x04:
            return False
        if _integer_content(data, children[0]) != b"\x01":
            return False
        private_key_size = children[1][2] - children[1][1]
        if private_key_size < 16 or private_key_size > 128:
            return False
        return all(child[0] in (0xA0, 0xA1) for child in children[2:])
    except (IndexError, ValueError):
        return False


def _sequence_contains_spki(data: bytes, sequence: Tuple[int, int, int, int], depth: int) -> bool:
    if depth > 8 or sequence[0] != 0x30:
        return False
    try:
        children = _sequence_children(data, sequence[1], sequence[2])
    except ValueError:
        return False
    for child in children:
        if child[0] != 0x30:
            continue
        try:
            grandchildren = _sequence_children(data, child[1], child[2])
        except ValueError:
            grandchildren = ()
        if (
            len(grandchildren) == 2
            and grandchildren[0][0] == 0x30
            and grandchildren[1][0] == 0x03
        ):
            try:
                oid = _first_oid_in_sequence(data, grandchildren[0])
            except ValueError:
                oid = b""
            if oid in _KEY_OIDS:
                return True
        if _sequence_contains_spki(data, child, depth + 1):
            return True
    return False


def _looks_like_x509_or_csr(data: bytes) -> bool:
    if len(data) < 32 or data[0] != 0x30:
        return False
    try:
        outer = _read_tlv(data, 0, len(data))
        if outer[0] != 0x30 or outer[3] != len(data):
            return False
        children = _sequence_children(data, outer[1], outer[2])
        if len(children) != 3:
            return False
        if children[0][0] != 0x30 or children[1][0] != 0x30 or children[2][0] != 0x03:
            return False
        _first_oid_in_sequence(data, children[1])
        return _sequence_contains_spki(data, children[0], 0)
    except (IndexError, ValueError):
        return False


def _looks_like_binary_der_key(data: bytes) -> bool:
    return (
        _looks_like_spki_or_pkcs8(data)
        or _looks_like_pkcs1_rsa(data)
        or _looks_like_sec1_ec_private_key(data)
        or _looks_like_x509_or_csr(data)
    )


def _encoded_key_candidates(data: bytes) -> Tuple[bytes, ...]:
    compact = b"".join(data.split())
    if len(compact) < 32 or len(compact) > _MAX_ENCODED_KEY_CANDIDATE_BYTES:
        return ()
    candidates = []
    if len(compact) % 2 == 0 and _HEX_KEY_CANDIDATE.fullmatch(compact) is not None:
        try:
            candidates.append(bytes.fromhex(compact.decode("ascii")))
        except (UnicodeDecodeError, ValueError):
            pass
    if len(compact) % 4 != 1 and _BASE64_KEY_CANDIDATE.fullmatch(compact) is not None:
        padded = compact + b"=" * (-len(compact) % 4)
        try:
            candidates.append(base64.b64decode(padded, altchars=b"-_", validate=True))
        except (ValueError, TypeError):
            pass
    return tuple(candidate for candidate in candidates if candidate)


def _looks_like_encoded_der_key(data: bytes) -> bool:
    return any(_looks_like_binary_der_key(candidate) for candidate in _encoded_key_candidates(data))


def _looks_like_der_key(data: bytes) -> bool:
    return _looks_like_binary_der_key(data.strip()) or _looks_like_encoded_der_key(data)


def _looks_like_openssh_wire_key(data: bytes) -> bool:
    if len(data) < 5:
        return False
    type_size = int.from_bytes(data[:4], "big")
    if type_size < 3 or type_size > 64 or len(data) < 4 + type_size:
        return False
    return data[4 : 4 + type_size].lower() in _SSH_PUBLIC_KEY_TYPES


def _looks_like_openssh_key(data: bytes) -> bool:
    lowered = data.lower()
    for token in lowered.split():
        if token.strip(_SSH_TOKEN_EDGE_CHARS) in _SSH_PUBLIC_KEY_TYPES:
            return True
    if _looks_like_openssh_wire_key(data):
        return True
    return any(
        _looks_like_openssh_wire_key(candidate)
        for candidate in _encoded_key_candidates(data)
    )


def _looks_like_jwk(data: bytes) -> bool:
    stripped = data.strip()
    if stripped.startswith(b"\xef\xbb\xbf"):
        stripped = stripped[3:].strip()
    lowered = stripped.lower()
    if not stripped.startswith(b"{") or re.search(rb'"kty"\s*:', lowered) is None:
        return False
    if any(marker in lowered for marker in _ASYMMETRIC_JWK_TYPES):
        return True
    try:
        value = json.loads(stripped.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return False
    if not isinstance(value, dict):
        return False
    kty = value.get("kty")
    return isinstance(kty, str) and kty.lower() in {"rsa", "ec", "okp"}


def shannon_entropy_bits(data: bytes) -> float:
    """Return a simple Shannon entropy estimate for a byte string.

    This is a screening estimate, not a measurement of how the key was
    generated. Uniform random keys pass comfortably while repeated characters,
    short alphabets, and human passwords fail closed.
    """
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    length = float(len(data))
    bits_per_byte = 0.0
    for count in counts:
        if count:
            probability = count / length
            bits_per_byte -= probability * math.log2(probability)
    return bits_per_byte * length


def _coerce_allow_weak(allow_weak_keys: Any) -> bool:
    if not isinstance(allow_weak_keys, bool):
        raise JwtGuardError(CONFIG_INVALID, "allow_weak_keys must be True or False")
    return allow_weak_keys


def validate_hmac_key(key: Any, algorithm: str, *, allow_weak_keys: bool = False) -> bytes:
    """Normalize and screen an HMAC secret, returning its raw bytes.

    ``allow_weak_keys`` disables only the length and Shannon entropy floors. It
    never disables type checks, empty key rejection, or asymmetric key confusion
    detection.
    """
    allow_weak = _coerce_allow_weak(allow_weak_keys)
    if algorithm not in HMAC_SPECS:
        raise JwtGuardError(KEY_INVALID, "unknown HMAC algorithm")
    spec = HMAC_SPECS[algorithm]
    if isinstance(key, HmacKey):
        if key.algorithm != algorithm:
            raise JwtGuardError(
                KEY_CONFUSION,
                "HMAC key is bound to a different algorithm",
            )
        material = key.secret
    elif isinstance(key, str):
        material = key.encode("utf-8")
    elif isinstance(key, (bytes, bytearray, memoryview)):
        material = bytes(key)
    else:
        raise JwtGuardError(KEY_INVALID, "HMAC secret must be bytes or text")
    if not material:
        raise JwtGuardError(KEY_INVALID, "HMAC secret must not be empty")
    if _PEM_MARKER.search(material):
        raise JwtGuardError(
            KEY_CONFUSION,
            "PEM key or certificate material was supplied as an HMAC secret",
        )
    if _looks_like_openssh_key(material):
        raise JwtGuardError(
            KEY_CONFUSION,
            "OpenSSH public key material was supplied as an HMAC secret",
        )
    if _looks_like_jwk(material):
        raise JwtGuardError(
            KEY_CONFUSION,
            "asymmetric JWK material was supplied as an HMAC secret",
        )
    if _looks_like_der_key(material):
        raise JwtGuardError(
            KEY_CONFUSION,
            "DER key material was supplied as an HMAC secret",
        )
    if allow_weak:
        return material
    if len(material) < spec.minimum_key_bytes:
        raise JwtGuardError(
            WEAK_KEY,
            "{} requires a secret of at least {} bytes".format(
                algorithm, spec.minimum_key_bytes
            ),
        )
    entropy = shannon_entropy_bits(material)
    if entropy < spec.minimum_entropy_bits:
        raise JwtGuardError(
            WEAK_KEY,
            "{} requires at least {} estimated entropy bits".format(
                algorithm, spec.minimum_entropy_bits
            ),
        )
    return material


class HmacKey:
    """Immutable HMAC key material bound to exactly one JOSE algorithm.

    Binding the algorithm at construction implements the RFC 8725 rule that a
    key must be used with exactly one algorithm. Keyring entries and key
    resolvers use this type so a rotated key cannot silently be reinterpreted
    under another HMAC digest.
    """

    __slots__ = ("_algorithm", "_locked", "_secret")

    def __init__(self, secret: Any, algorithm: str, *, allow_weak_keys: bool = False) -> None:
        if algorithm not in HMAC_SPECS:
            raise JwtGuardError(KEY_INVALID, "HmacKey algorithm must be HS256, HS384, or HS512")
        normalized = validate_hmac_key(secret, algorithm, allow_weak_keys=allow_weak_keys)
        object.__setattr__(self, "_algorithm", algorithm)
        object.__setattr__(self, "_secret", normalized)
        object.__setattr__(self, "_locked", True)

    def __setattr__(self, name: str, value: Any) -> None:
        if getattr(self, "_locked", False):
            raise AttributeError("HmacKey is immutable")
        object.__setattr__(self, name, value)

    def __delattr__(self, name: str) -> None:
        if getattr(self, "_locked", False):
            raise AttributeError("HmacKey is immutable")
        object.__delattr__(self, name)

    @property
    def algorithm(self) -> str:
        """Return the single algorithm this key is bound to."""
        return self._algorithm

    @property
    def secret(self) -> bytes:
        """Return immutable raw key bytes."""
        return self._secret

    @classmethod
    def generate(cls, algorithm: str) -> "HmacKey":
        """Generate a random key of the algorithm minimum length."""
        if algorithm not in HMAC_SPECS:
            raise JwtGuardError(KEY_INVALID, "HmacKey algorithm must be HS256, HS384, or HS512")
        return cls(secrets.token_bytes(HMAC_SPECS[algorithm].minimum_key_bytes), algorithm)

    def __repr__(self) -> str:
        return "HmacKey(algorithm={!r}, secret=<redacted>)".format(self._algorithm)


def hmac_sign(algorithm: str, key: Any, signing_input: bytes, *, allow_weak_keys: bool = False) -> bytes:
    """Return the raw HMAC signature for the signing input."""
    material = validate_hmac_key(key, algorithm, allow_weak_keys=allow_weak_keys)
    spec = HMAC_SPECS[algorithm]
    return hmac.new(material, signing_input, spec.digest).digest()


def hmac_verify(
    algorithm: str,
    key: Any,
    signing_input: bytes,
    signature: bytes,
    *,
    allow_weak_keys: bool = False,
) -> None:
    """Verify a raw HMAC signature in constant time."""
    material = validate_hmac_key(key, algorithm, allow_weak_keys=allow_weak_keys)
    spec = HMAC_SPECS[algorithm]
    expected = hmac.new(material, signing_input, spec.digest).digest()
    if len(signature) != len(expected) or not hmac.compare_digest(expected, signature):
        raise JwtGuardError(SIGNATURE_INVALID, "signature does not match")


def digest_size(algorithm: str) -> int:
    """Return the raw signature size for a supported HMAC algorithm."""
    if algorithm not in HMAC_SPECS:
        raise JwtGuardError(KEY_INVALID, "unknown HMAC algorithm")
    return hashlib.new(HMAC_SPECS[algorithm].digest).digest_size


__all__ = [
    "HMAC_SPECS",
    "MINIMUM_ENTROPY_BITS",
    "MINIMUM_SECRET_BYTES",
    "SUPPORTED_HMAC_ALGORITHMS",
    "HmacKey",
    "HmacSpec",
    "digest_size",
    "hmac_sign",
    "hmac_verify",
    "shannon_entropy_bits",
    "validate_hmac_key",
]
