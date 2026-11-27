"""Shared helpers for the pyjwtguard test suite."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import unittest

from pyjwtguard import HmacKey, JwtGuardError, verify_jwt

NOW = 1_700_000_000
HS256_SECRET = "0123456789abcdef0123456789abcdef"
HS384_SECRET = "0123456789abcdef0123456789abcdef0123456789abcdef"
HS512_SECRET = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
SECRETS = {"HS256": HS256_SECRET, "HS384": HS384_SECRET, "HS512": HS512_SECRET}
HS256_KEY = HmacKey(HS256_SECRET, "HS256")


def strong_secret(algorithm):
    return SECRETS[algorithm]


def b64(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def json_bytes(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def json_segment(value):
    return b64(json_bytes(value))


def secret_bytes(secret):
    if isinstance(secret, HmacKey):
        return secret.secret
    if isinstance(secret, str):
        return secret.encode("utf-8")
    return bytes(secret)


def sign_segments(header_segment, payload_segment, secret=HS256_SECRET, algorithm="HS256"):
    digest = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}[algorithm]
    signing_input = (header_segment + "." + payload_segment).encode("ascii")
    signature = hmac.new(secret_bytes(secret), signing_input, digest).digest()
    return signing_input.decode("ascii") + "." + b64(signature)


def manual_token(header=None, payload=None, secret=HS256_SECRET, algorithm="HS256", signature=None):
    if header is None:
        header = {"alg": algorithm}
    if payload is None:
        payload = {"exp": NOW + 300}
    header_segment = header if isinstance(header, str) else json_segment(header)
    payload_segment = payload if isinstance(payload, str) else json_segment(payload)
    if signature is not None:
        return header_segment + "." + payload_segment + "." + signature
    return sign_segments(header_segment, payload_segment, secret, algorithm)


def verify(token, key=HS256_SECRET, algorithms=None, **kwargs):
    if algorithms is None:
        algorithms = ["HS256"]
    kwargs.setdefault("now", NOW)
    return verify_jwt(token, key, algorithms=algorithms, **kwargs)


class GuardTestCase(unittest.TestCase):
    def assertCode(self, code, func, *args, **kwargs):
        with self.assertRaises(JwtGuardError) as caught:
            func(*args, **kwargs)
        self.assertEqual(
            code,
            caught.exception.code,
            "expected {}, got {}: {}".format(code, caught.exception.code, caught.exception),
        )
        return caught.exception

    def assertVerifyCode(self, code, token, key=HS256_SECRET, **kwargs):
        return self.assertCode(code, verify, token, key, **kwargs)


def pem_public_key(label="PUBLIC KEY"):
    return (
        "-----BEGIN {}-----\n"
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE0123456789abcdef\n"
        "-----END {}-----\n"
    ).format(label, label)


def pem_private_key():
    return pem_public_key("PRIVATE KEY")


def der_tlv(tag, value):
    length = len(value)
    if length < 128:
        prefix = bytes([tag, length])
    elif length < 256:
        prefix = bytes([tag, 0x81, length])
    else:
        prefix = bytes([tag, 0x82, length >> 8, length & 0xFF])
    return prefix + value


def spki_der(oid_hex):
    oid = der_tlv(0x06, bytes.fromhex(oid_hex))
    algorithm = der_tlv(0x30, oid + der_tlv(0x05, b""))
    bitstring = der_tlv(0x03, b"\x00" + bytes(range(1, 90)))
    return der_tlv(0x30, algorithm + bitstring)


def pkcs1_rsa_public_der():
    modulus = der_tlv(0x02, b"\x00" + b"\x88" * 128)
    exponent = der_tlv(0x02, b"\x01\x00\x01")
    return der_tlv(0x30, modulus + exponent)


def pkcs1_rsa_private_der():
    version = der_tlv(0x02, b"\x00")
    modulus = der_tlv(0x02, b"\x00" + b"\x88" * 128)
    exponent = der_tlv(0x02, b"\x01\x00\x01")
    rest = b"".join(der_tlv(0x02, b"\x01" + b"\x77" * 64) for _ in range(6))
    return der_tlv(0x30, version + modulus + exponent + rest)


def pkcs8_private_der(oid_hex="2a864886f70d010101"):
    version = der_tlv(0x02, b"\x00")
    oid = der_tlv(0x06, bytes.fromhex(oid_hex))
    algorithm = der_tlv(0x30, oid + der_tlv(0x05, b""))
    private = der_tlv(0x04, bytes(range(32)))
    return der_tlv(0x30, version + algorithm + private)


def sec1_ec_private_der():
    version = der_tlv(0x02, b"\x01")
    private = der_tlv(0x04, bytes(range(32)))
    curve_oid = der_tlv(0x06, bytes.fromhex("2a8648ce3d030107"))
    parameters = der_tlv(0xA0, curve_oid)
    public_point = der_tlv(0x03, b"\x00\x04" + bytes(range(1, 65)))
    public = der_tlv(0xA1, public_point)
    return der_tlv(0x30, version + private + parameters + public)


def der_name():
    common_name_oid = der_tlv(0x06, bytes.fromhex("550403"))
    attribute = der_tlv(0x30, common_name_oid + der_tlv(0x13, b"example"))
    return der_tlv(0x30, der_tlv(0x31, attribute))


def der_validity():
    return der_tlv(0x30, der_tlv(0x17, b"260101000000Z") + der_tlv(0x17, b"270101000000Z"))


def der_signature_algorithm():
    oid = der_tlv(0x06, bytes.fromhex("2a864886f70d01010b"))
    return der_tlv(0x30, oid + der_tlv(0x05, b""))


def x509_certificate_der():
    version = der_tlv(0xA0, der_tlv(0x02, b"\x02"))
    serial = der_tlv(0x02, b"\x01")
    name = der_name()
    tbs = der_tlv(
        0x30,
        version
        + serial
        + der_signature_algorithm()
        + name
        + der_validity()
        + name
        + spki_der("2a864886f70d010101"),
    )
    signature = der_tlv(0x03, b"\x00" + bytes(range(64)))
    return der_tlv(0x30, tbs + der_signature_algorithm() + signature)


def x509_csr_der():
    version = der_tlv(0x02, b"\x00")
    attributes = der_tlv(0xA0, b"")
    info = der_tlv(
        0x30,
        version + der_name() + spki_der("2a864886f70d010101") + attributes,
    )
    signature = der_tlv(0x03, b"\x00" + bytes(range(64)))
    return der_tlv(0x30, info + der_signature_algorithm() + signature)


RSA_SPKI_DER = spki_der("2a864886f70d010101")
EC_SPKI_DER = spki_der("2a8648ce3d0201")
ED25519_SPKI_DER = spki_der("2b6570")
RSA_PKCS1_DER = pkcs1_rsa_public_der()
RSA_PKCS1_PRIVATE_DER = pkcs1_rsa_private_der()
RSA_PKCS8_DER = pkcs8_private_der()
SEC1_EC_PRIVATE_DER = sec1_ec_private_der()
X509_CERTIFICATE_DER = x509_certificate_der()
X509_CSR_DER = x509_csr_der()
