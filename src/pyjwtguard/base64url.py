"""Strict unpadded base64url encoding and decoding.

The JOSE base64url alphabet contains only ``A-Z``, ``a-z``, ``0-9``, ``-`` and
``_``. Padding, whitespace, the standard base64 alphabet, and encodings with
non-zero trailing padding bits are all rejected. Rejecting non-canonical
encodings closes signature malleability: without it the same byte string can
appear as several distinct token strings.
"""

from __future__ import annotations

import base64
import binascii
import re

from .errors import BASE64_INVALID, BASE64_NONCANONICAL, JwtGuardError

_ALPHABET = re.compile(r"[A-Za-z0-9_-]*")


def b64url_encode(data: bytes) -> str:
    """Encode bytes as canonical unpadded base64url text."""
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("b64url_encode expects a bytes-like object")
    return base64.urlsafe_b64encode(bytes(data)).rstrip(b"=").decode("ascii")


def b64url_decode(segment: str) -> bytes:
    """Decode one base64url segment, rejecting non-canonical input.

    Raises:
        JwtGuardError: with code ``BASE64_INVALID`` for wrong types, illegal
            characters, or impossible lengths, and ``BASE64_NONCANONICAL``
            when unused trailing bits are not zero.
    """
    if not isinstance(segment, str):
        raise JwtGuardError(BASE64_INVALID, "base64url segment must be text")
    if _ALPHABET.fullmatch(segment) is None:
        raise JwtGuardError(
            BASE64_INVALID,
            "segment contains characters outside the base64url alphabet",
        )
    if len(segment) % 4 == 1:
        raise JwtGuardError(BASE64_INVALID, "segment has an impossible base64url length")
    padding = "=" * (-len(segment) % 4)
    try:
        raw = base64.urlsafe_b64decode((segment + padding).encode("ascii"))
    except (binascii.Error, ValueError) as exc:
        raise JwtGuardError(BASE64_INVALID, "segment is not valid base64url") from exc
    if b64url_encode(raw) != segment:
        raise JwtGuardError(
            BASE64_NONCANONICAL,
            "segment is not canonical base64url, trailing bits must be zero",
        )
    return raw


__all__ = ["b64url_decode", "b64url_encode"]
