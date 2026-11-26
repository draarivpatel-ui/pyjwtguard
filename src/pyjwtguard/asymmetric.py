"""Pluggable asymmetric signing and verification interfaces.

pyjwtguard ships no asymmetric cryptography of its own because the Python
standard library has none. Instead it exposes small structural protocols. A
caller can adapt ``cryptography``, an HSM, or a remote KMS without adding a
runtime dependency to this package. Every structural defense still runs before
and after the adapter is consulted.

``AlgorithmSigner`` and ``AlgorithmVerifier`` are the role specific protocols.
``AlgorithmProvider`` combines both roles for implementations such as a local
key manager that can sign and verify with the same key handle.
"""

from __future__ import annotations

from typing import Any, Mapping, Protocol


class AlgorithmVerifier(Protocol):
    """Adapter that verifies RS256, ES256, EdDSA, or similar signatures."""

    def supports(self, algorithm: str) -> bool:
        """Return True when this adapter can verify ``algorithm``."""

    def verify(
        self,
        algorithm: str,
        signing_input: bytes,
        signature: bytes,
        header: Mapping[str, Any],
    ) -> bool:
        """Return True only when the signature is valid for the input."""


class AlgorithmSigner(Protocol):
    """Adapter that signs with a private key held outside this library."""

    def supports(self, algorithm: str) -> bool:
        """Return True when this adapter can sign with ``algorithm``."""

    def sign(
        self,
        algorithm: str,
        signing_input: bytes,
        header: Mapping[str, Any],
    ) -> bytes:
        """Return the raw signature bytes for the signing input."""


class AlgorithmProvider(AlgorithmSigner, AlgorithmVerifier, Protocol):
    """Combined signer and verifier protocol for external key systems."""


AsymmetricSigner = AlgorithmSigner
AsymmetricVerifier = AlgorithmVerifier

__all__ = [
    "AlgorithmProvider",
    "AlgorithmSigner",
    "AlgorithmVerifier",
    "AsymmetricSigner",
    "AsymmetricVerifier",
]
