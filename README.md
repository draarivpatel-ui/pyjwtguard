# pyjwtguard

pyjwtguard is a zero-dependency Python library for hardened compact JWS and JWT signing, verification, and structural inspection. It targets Python 3.9 through 3.13 and uses only the standard library at runtime.

The built-in cryptographic implementation is intentionally narrow: constant-time HMAC for HS256, HS384, and HS512. RSA, ECDSA, EdDSA, HSM, and KMS systems are supported through an explicit provider protocol, never through silent fallback or header-driven key selection.

## Security posture

- `algorithms` is mandatory on every verification call and is matched exactly and case sensitively.
- `none` is rejected in every casing and can never be allowlisted or signed.
- HMAC verification uses `hmac.compare_digest`.
- HMAC secrets must meet minimum lengths of 32, 48, and 64 bytes for HS256, HS384, and HS512.
- HMAC secrets also pass a conservative Shannon entropy screen of 128, 192, and 256 estimated bits. `allow_weak_keys=True` is an explicit legacy or test opt-out and never disables key-confusion detection.
- PEM armored keys, certificates, and certificate requests, OpenSSH public keys in text, wire, or encoded wire form, asymmetric JWKs, common DER key and certificate encodings, and base64 or hex encoded forms of that DER material are rejected when passed as HMAC secrets. This blocks the classic RS256 to HS256 public-key confusion attack.
- `HmacKey` binds key material to exactly one algorithm, following the RFC 8725 rule that each key must be used with exactly one algorithm.
- Key rotation uses validated `kid` lookup through a keyring or resolver. Path separators, traversal, control characters, SQL metacharacters, encoded traversal, invisible formatting characters, and overlong identifiers are rejected.
- JSON parsing rejects duplicate keys at every nesting level, including keys hidden behind Unicode escapes.
- Base64url must be canonical unpadded base64url. Padding, whitespace, the standard base64 alphabet, impossible lengths, and non-zero trailing pad bits are rejected.
- Embedded key and remote key headers `jwk`, `jku`, `x5u`, and `x5c` are rejected by default. pyjwtguard never fetches them.
- `crit` cannot name registered headers, duplicates, missing headers, or unknown critical extensions. Callers must explicitly declare understood private extensions.
- `b64: false` is rejected unless explicitly enabled. It is only for closed JWS profiles because RFC 7797 says JWTs must not use it.
- Tokens are size capped before decoding. The default cap is 8192 bytes.
- Claims are parsed only after signature verification succeeds.
- `exp`, `nbf`, `iat`, `iss`, `aud`, `sub`, `jti`, required claims, explicit type, and `max_age` are strictly validated. Required claims must also be non-null and non-empty when they are strings, arrays, or objects. `max_age` fails closed when `iat` is absent.
- Numeric dates reject booleans, strings, non-finite values, and integers outside the supported year 1 to year 9999 timestamp range.
- Every failure is a `JwtGuardError` with a stable machine-readable `code`.

## Non-goals

pyjwtguard does not implement JWE encryption, nested JWTs, JWS JSON serialization, detached payloads, key fetching, certificate chain validation, or issuer key discovery. It does not make network calls. Applications remain responsible for binding issuer identities to trusted keys and for choosing currently appropriate asymmetric algorithms in external providers.

## Installation

```bash
python3 -m pip install pyjwtguard
```

## HMAC quickstart

```python
import time

from pyjwtguard import HmacKey, sign_jwt, verify_jwt

key = HmacKey.generate("HS256")
now = int(time.time())

token = sign_jwt(
    {
        "iss": "https://issuer.example",
        "sub": "user-123",
        "aud": "api",
        "iat": now,
        "nbf": now,
        "exp": now + 300,
        "jti": "unique-token-id",
    },
    key,
    headers={"kid": "2026-01"},
)

claims = verify_jwt(
    token,
    key,
    algorithms=["HS256"],
    issuer="https://issuer.example",
    audience="api",
    subject="user-123",
    max_age=300,
)
```

`require_exp` is true by default. Pass `leeway` only for real clock skew, normally a few seconds. Pass `expected_type` when an application profile uses explicit typing.

## Key rotation

Keyring values must be `HmacKey` objects. This is deliberate: raw bytes do not carry their algorithm binding.

```python
from pyjwtguard import HmacKey, sign_jwt, verify_jwt

current = HmacKey.generate("HS256")
previous = HmacKey.generate("HS256")
keyring = {
    "2026-01": previous,
    "2026-02": current,
}

token = sign_jwt({"sub": "user-123", "exp": 2000000000}, current, headers={"kid": "2026-02"})
claims = verify_jwt(token, keyring=keyring, algorithms=["HS256"], now=1500000000)
```

A resolver can adapt a database or secret manager. It receives only the already validated `kid` string and must return an `HmacKey`.

```python
def resolve_key(kid):
    return load_hmac_key_from_trusted_store(kid)

claims = verify_jwt(token, key_resolver=resolve_key, algorithms=["HS256"])
```

`load_hmac_key_from_trusted_store` is application code. The resolver must never treat `kid` as a filesystem path, SQL fragment, or URL.

## External asymmetric providers

The standard library has no RSA or elliptic curve cryptography. Implement `AlgorithmSigner`, `AlgorithmVerifier`, or the combined `AlgorithmProvider` protocol with a vetted external key system. This example is an adapter sketch, not a runtime dependency of pyjwtguard:

```python
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

class RS256Provider:
    def __init__(self, public_key, private_key=None):
        self.public_key = public_key
        self.private_key = private_key

    def supports(self, algorithm):
        return algorithm == "RS256"

    def verify(self, algorithm, signing_input, signature, header):
        try:
            self.public_key.verify(
                signature,
                signing_input,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
            return True
        except InvalidSignature:
            return False

    def sign(self, algorithm, signing_input, header):
        if self.private_key is None:
            raise ValueError("private key unavailable")
        return self.private_key.sign(
            signing_input,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
```

Use it explicitly:

```python
provider = RS256Provider(public_key, private_key)
token = sign_jwt(claims, provider=provider, algorithm="RS256")
verified = verify_jwt(token, algorithms=["RS256"], providers=[provider])
```

The provider owns asymmetric key validation, key rotation, curve policy, and private-key protection. pyjwtguard still enforces token structure, exact algorithm matching, header policy, canonical encoding, and claim validation. Providers cannot override the built-in HMAC implementation.

## Unverified inspection

Use `decode_unverified` only for diagnostics, routing experiments, or debugging. Its output is attacker controlled because no signature or claim validation has occurred.

```python
from pyjwtguard import decode_unverified

inspection = decode_unverified(token)
print(inspection.header, inspection.claims, inspection.verified)
```

`verified` is always `False`. The function is deliberately named so it cannot be mistaken for signature verification. The command line interface exposes the same diagnostic operation:

```bash
pyjwtguard inspect "$TOKEN"
```

## Error handling

```python
from pyjwtguard import JwtGuardError, verify_jwt

try:
    claims = verify_jwt(token, key, algorithms=["HS256"])
except JwtGuardError as exc:
    if exc.code == "TOKEN_EXPIRED":
        refresh_or_reauthenticate()
    else:
        reject_token()
```

Branch on `exc.code`, not the human-readable message. The complete stable list is exported as `ERROR_CODES`.

## Test evidence and development

The offline unittest suite currently contains 640 real tests covering RFC 7515 vectors, RFC 7797 shapes, RFC 8725 best practices, algorithm confusion, key rotation, duplicate-key parser differentials, base64url malleability, critical headers, strict claims, providers, inspection, and CLI behavior. All 640 tests passed in the local verification run for this commit.

Run the suite with:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests
```

The project has no runtime dependencies and no third-party test dependencies.
