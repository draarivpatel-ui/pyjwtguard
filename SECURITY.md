# Security Policy

## Supported versions

Version 1.x receives security fixes.

## Reporting a vulnerability

Please use GitHub's private security advisory form at <https://github.com/draarivpatel-ui/pyjwtguard/security/advisories/new>. Do not open a public issue for an undisclosed vulnerability.

Include the affected version, a minimal token or code reproduction, the expected behavior, and the observed behavior. Do not include real secrets, private keys, production tokens, or personal data. Reports are acknowledged within seven days. Fixes are released as patch versions with a changelog entry.

## In scope

- Signature verification bypasses
- `none` algorithm acceptance or case-variant bypasses
- Algorithm confusion, including RS256 or ES256 public keys accepted as HMAC secrets
- HMAC comparison or key-strength policy bypasses
- Duplicate JSON key parser differentials
- Non-canonical base64url signature malleability
- `kid` traversal, injection, or key-type confusion in keyring and resolver lookup
- `crit`, `b64`, `jwk`, `jku`, `x5u`, or `x5c` policy bypasses
- Claim validation bypasses for `exp`, `nbf`, `iat`, `iss`, `aud`, `sub`, `jti`, or `max_age`
- Token size or parser behavior that causes a practical denial of service within documented limits
- Provider protocol behavior that silently accepts a wrong algorithm or a non-boolean verification result

## Out of scope

- Vulnerabilities in applications using this library
- Weaknesses in external asymmetric providers, key servers, HSMs, KMS systems, or the `cryptography` package
- Issuer-to-key binding decisions that only the application can make
- Denial of service from inputs above the documented token size limit
- Social engineering or physical access
- Use of `allow_weak_keys=True`, `allow_remote_headers=True`, or `allow_unencoded_payload=True` outside a deliberate application profile

## Design notes

pyjwtguard is defensive only. It performs no network access, filesystem access, subprocess execution, browser interaction, or remote key fetching. Built-in cryptography is limited to HMAC using Python `hmac` and `hashlib`. External asymmetric cryptography is always explicit through the provider protocol.

Claims are parsed only after the signature is verified. Diagnostic decoding is available only through explicitly named unverified inspection APIs.
