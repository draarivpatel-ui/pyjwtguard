"""HMAC key strength, key confusion, and signature primitive tests."""

import base64
import struct
import unittest

from pyjwtguard import HmacKey, sign_jwt
from pyjwtguard.crypto import digest_size, shannon_entropy_bits, validate_hmac_key

from _support import (
    EC_SPKI_DER,
    ED25519_SPKI_DER,
    GuardTestCase,
    HS256_SECRET,
    NOW,
    RSA_PKCS1_DER,
    RSA_PKCS1_PRIVATE_DER,
    RSA_PKCS8_DER,
    RSA_SPKI_DER,
    SEC1_EC_PRIVATE_DER,
    X509_CERTIFICATE_DER,
    X509_CSR_DER,
    manual_token,
    pem_private_key,
    pem_public_key,
    strong_secret,
    verify,
)


class HmacSecretAcceptanceTests(GuardTestCase):
    pass


def _make_acceptance_test(algorithm, kind):
    def test(self):
        secret = strong_secret(algorithm)
        if kind == "bytes":
            key = secret.encode("utf-8")
        elif kind == "bytearray":
            key = bytearray(secret.encode("utf-8"))
        elif kind == "memoryview":
            key = memoryview(secret.encode("utf-8"))
        else:
            key = secret
        token = manual_token(header={"alg": algorithm}, secret=secret, algorithm=algorithm)
        claims = verify(token, key, algorithms=[algorithm])
        self.assertEqual(NOW + 300, claims["exp"])
    return test


for _algorithm in ("HS256", "HS384", "HS512"):
    for _kind in ("str", "bytes", "bytearray", "memoryview"):
        setattr(
            HmacSecretAcceptanceTests,
            "test_{}_accepts_{}_secret".format(_algorithm.lower(), _kind),
            _make_acceptance_test(_algorithm, _kind),
        )


class HmacMinimumLengthTests(GuardTestCase):
    pass


def _make_exact_minimum_test(algorithm):
    def test(self):
        secret = strong_secret(algorithm)
        token = sign_jwt({"exp": NOW + 300}, secret, algorithm=algorithm)
        self.assertEqual(NOW + 300, verify(token, secret, algorithms=[algorithm])["exp"])
    return test


def _make_short_key_test(algorithm, length):
    def test(self):
        secret = "x" * length
        self.assertCode("WEAK_KEY", sign_jwt, {"exp": NOW + 300}, secret, algorithm=algorithm)
    return test


def _make_empty_key_test(algorithm):
    def test(self):
        self.assertCode("KEY_INVALID", sign_jwt, {"exp": NOW + 300}, "", algorithm=algorithm)
    return test


for _algorithm in ("HS256", "HS384", "HS512"):
    setattr(HmacMinimumLengthTests, "test_{}_accepts_exact_minimum_high_entropy_secret".format(_algorithm.lower()), _make_exact_minimum_test(_algorithm))
    setattr(HmacMinimumLengthTests, "test_{}_rejects_empty_secret".format(_algorithm.lower()), _make_empty_key_test(_algorithm))
    for _length in (1, {"HS256": 31, "HS384": 47, "HS512": 63}[_algorithm]):
        setattr(
            HmacMinimumLengthTests,
            "test_{}_rejects_{}_byte_secret".format(_algorithm.lower(), _length),
            _make_short_key_test(_algorithm, _length),
        )


class HmacEntropyTests(GuardTestCase):
    pass


def _make_low_entropy_test(algorithm, secret, label):
    def test(self):
        self.assertCode("WEAK_KEY", validate_hmac_key, secret, algorithm)
    return test


for _algorithm, _minimum in (("HS256", 32), ("HS384", 48), ("HS512", 64)):
    for _label, _secret in (
        ("repeated_a", "a" * _minimum),
        ("alternating_ab", "ab" * (_minimum // 2)),
        ("repeated_digits", "0123456789" * ((_minimum // 10) + 1)),
    ):
        _secret = _secret[:_minimum]
        setattr(
            HmacEntropyTests,
            "test_{}_rejects_{}".format(_algorithm.lower(), _label),
            _make_low_entropy_test(_algorithm, _secret, _label),
        )


class EntropyMeasurementTests(GuardTestCase):
    def test_empty_entropy_is_zero(self):
        self.assertEqual(0.0, shannon_entropy_bits(b""))

    def test_single_repeated_byte_entropy_is_zero(self):
        self.assertEqual(0.0, shannon_entropy_bits(b"a" * 64))

    def test_uniform_sixteen_character_alphabet_has_expected_entropy(self):
        self.assertAlmostEqual(128.0, shannon_entropy_bits(("0123456789abcdef" * 2).encode("ascii")))

    def test_binary_key_with_uniform_bytes_passes_hs256_floor(self):
        key = bytes(range(32))
        self.assertEqual(key, validate_hmac_key(key, "HS256"))

    def test_allow_weak_keys_permits_short_secret(self):
        key = validate_hmac_key(b"short", "HS256", allow_weak_keys=True)
        self.assertEqual(b"short", key)

    def test_allow_weak_keys_permits_low_entropy_secret(self):
        key = validate_hmac_key("a" * 32, "HS256", allow_weak_keys=True)
        self.assertEqual(("a" * 32).encode("utf-8"), key)

    def test_allow_weak_keys_must_be_boolean(self):
        self.assertCode("CONFIG_INVALID", validate_hmac_key, b"x", "HS256", allow_weak_keys=1)

    def test_unknown_hmac_algorithm_is_rejected(self):
        self.assertCode("KEY_INVALID", validate_hmac_key, b"x" * 32, "HS999")

    def test_non_key_type_is_rejected(self):
        self.assertCode("KEY_INVALID", validate_hmac_key, object(), "HS256")


class AsymmetricKeyConfusionTests(GuardTestCase):
    pass


_PEM_CASES = [
    ("public_key", pem_public_key()),
    ("private_key", pem_private_key()),
    ("rsa_public_key", pem_public_key("RSA PUBLIC KEY")),
    ("rsa_private_key", pem_public_key("RSA PRIVATE KEY")),
    ("ec_private_key", pem_public_key("EC PRIVATE KEY")),
    ("openssh_private_key", pem_public_key("OPENSSH PRIVATE KEY")),
    ("certificate", pem_public_key("CERTIFICATE")),
    ("trusted_certificate", pem_public_key("TRUSTED CERTIFICATE")),
    ("x509_certificate", pem_public_key("X509 CERTIFICATE")),
    ("certificate_request", pem_public_key("CERTIFICATE REQUEST")),
    ("new_certificate_request", pem_public_key("NEW CERTIFICATE REQUEST")),
    ("lowercase_marker", pem_public_key().lower()),
]

_DER_CASES = [
    ("rsa_spki", RSA_SPKI_DER),
    ("ec_spki", EC_SPKI_DER),
    ("ed25519_spki", ED25519_SPKI_DER),
    ("rsa_pkcs1", RSA_PKCS1_DER),
    ("rsa_pkcs1_private", RSA_PKCS1_PRIVATE_DER),
    ("rsa_pkcs8", RSA_PKCS8_DER),
    ("sec1_ec_private", SEC1_EC_PRIVATE_DER),
    ("x509_certificate", X509_CERTIFICATE_DER),
    ("x509_certificate_trailing_whitespace", X509_CERTIFICATE_DER + b"\r\n"),
    ("x509_csr", X509_CSR_DER),
]

_ENCODED_DER_CASES = [
    ("base64_standard", base64.b64encode(RSA_SPKI_DER)),
    ("base64_urlsafe_unpadded", base64.urlsafe_b64encode(X509_CERTIFICATE_DER).rstrip(b"=")),
    ("hexadecimal", SEC1_EC_PRIVATE_DER.hex().encode("ascii")),
]

_SSH_WIRE_CASES = [
    ("rsa", struct.pack(">I", 7) + b"ssh-rsa" + b"\x00" * 64),
    ("ed25519", struct.pack(">I", 11) + b"ssh-ed25519" + b"\x00" * 32),
]

_ENCODED_SSH_WIRE_CASES = [
    ("base64_rsa", base64.b64encode(_SSH_WIRE_CASES[0][1])),
    ("hex_rsa", _SSH_WIRE_CASES[0][1].hex().encode("ascii")),
]

_TEXT_KEY_CASES = [
    ("jwk_rsa", '{"kty":"RSA","n":"abc","e":"AQAB"}' + "x" * 32),
    ("jwk_utf8_bom", '\ufeff{"kty":"RSA","n":"abc","e":"AQAB"}' + "x" * 32),
    ("jwk_spaced_kty_invalid_json", '{"kty" : "RSA", "n":"abc"}' + "x" * 32),
    ("jwk_ec", '{"kty":"EC","crv":"P-256","x":"abc","y":"def"}' + "x" * 32),
    ("jwk_okp", '{"kty":"OKP","crv":"Ed25519","x":"abc"}' + "x" * 32),
    ("openssh_rsa", "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ" + "x" * 32),
    ("openssh_dss", "ssh-dss AAAAB3NzaC1kc3MAAACB" + "x" * 32),
    ("openssh_rsa_sha2", "rsa-sha2-256 AAAAB3NzaC1yc2EAAAADAQABAAABAQ" + "x" * 32),
    ("openssh_ed25519", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI" + "x" * 32),
    ("openssh_ecdsa", "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTY" + "x" * 32),
    ("openssh_fido_ed25519", "sk-ssh-ed25519@openssh.com AAAA" + "x" * 32),
    ("openssh_fido_ecdsa", "sk-ecdsa-sha2-nistp256@openssh.com AAAA" + "x" * 32),
    ("openssh_authorized_key_options", 'command="echo example",no-pty ssh-rsa AAAAB3NzaC1yc2E' + "x" * 32),
    ("openssh_after_comment_line", "# generated key\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5" + "x" * 32),
]


def _make_confusion_test(kind, material):
    def test(self):
        self.assertCode("KEY_CONFUSION", validate_hmac_key, material, "HS256", allow_weak_keys=True)
    return test


for _name, _material in _PEM_CASES:
    setattr(AsymmetricKeyConfusionTests, "test_pem_{}_is_rejected".format(_name), _make_confusion_test("pem", _material))
for _name, _material in _DER_CASES:
    setattr(AsymmetricKeyConfusionTests, "test_der_{}_is_rejected".format(_name), _make_confusion_test("der", _material))
for _name, _material in _ENCODED_DER_CASES:
    setattr(AsymmetricKeyConfusionTests, "test_encoded_der_{}_is_rejected".format(_name), _make_confusion_test("encoded", _material))
for _name, _material in _SSH_WIRE_CASES:
    setattr(AsymmetricKeyConfusionTests, "test_openssh_wire_{}_is_rejected".format(_name), _make_confusion_test("wire", _material))
for _name, _material in _ENCODED_SSH_WIRE_CASES:
    setattr(AsymmetricKeyConfusionTests, "test_encoded_openssh_wire_{}_is_rejected".format(_name), _make_confusion_test("encoded_wire", _material))
for _name, _material in _TEXT_KEY_CASES:
    setattr(AsymmetricKeyConfusionTests, "test_text_{}_is_rejected".format(_name), _make_confusion_test("text", _material))


class KeyConfusionIntegrationTests(GuardTestCase):
    def test_pem_public_key_cannot_verify_forged_hs256_token(self):
        pem = pem_public_key()
        forged = manual_token(secret=pem)
        self.assertVerifyCode("KEY_CONFUSION", forged, pem)

    def test_der_public_key_cannot_verify_forged_hs256_token(self):
        forged = manual_token(secret=RSA_SPKI_DER)
        self.assertVerifyCode("KEY_CONFUSION", forged, RSA_SPKI_DER)

    def test_x509_certificate_cannot_verify_forged_hs256_token(self):
        forged = manual_token(secret=X509_CERTIFICATE_DER)
        self.assertVerifyCode("KEY_CONFUSION", forged, X509_CERTIFICATE_DER, allow_weak_keys=True)

    def test_sec1_ec_private_key_cannot_verify_forged_hs256_token(self):
        forged = manual_token(secret=SEC1_EC_PRIVATE_DER)
        self.assertVerifyCode("KEY_CONFUSION", forged, SEC1_EC_PRIVATE_DER, allow_weak_keys=True)

    def test_normal_binary_secret_starting_with_sequence_tag_is_accepted(self):
        secret = b"\x30" + bytes(range(1, 32))
        token = manual_token(secret=secret)
        self.assertEqual(NOW + 300, verify(token, secret)["exp"])

    def test_normal_hex_secret_is_not_mistaken_for_encoded_key_material(self):
        secret = HS256_SECRET.encode("ascii")
        self.assertEqual(secret, validate_hmac_key(secret, "HS256", allow_weak_keys=True))

    def test_normal_base64_secret_is_not_mistaken_for_encoded_key_material(self):
        secret = base64.urlsafe_b64encode(bytes(range(32))).rstrip(b"=")
        self.assertEqual(secret, validate_hmac_key(secret, "HS256", allow_weak_keys=True))

    def test_hmac_key_wrong_algorithm_binding_is_rejected(self):
        wrong = HmacKey(strong_secret("HS384"), "HS384")
        token = manual_token()
        self.assertVerifyCode("KEY_CONFUSION", token, wrong)

    def test_hmac_key_correct_algorithm_binding_is_accepted(self):
        key = HmacKey(HS256_SECRET, "HS256")
        token = sign_jwt({"exp": NOW + 300}, key)
        self.assertEqual(NOW + 300, verify(token, key)["exp"])

    def test_hmac_key_repr_does_not_include_secret(self):
        key = HmacKey(HS256_SECRET, "HS256")
        self.assertNotIn(HS256_SECRET, repr(key))
        self.assertIn("redacted", repr(key))

    def test_hmackey_is_immutable(self):
        key = HmacKey(HS256_SECRET, "HS256")
        with self.assertRaises(AttributeError):
            key._algorithm = "HS512"
        with self.assertRaises(AttributeError):
            key._secret = b"replacement"
        with self.assertRaises(AttributeError):
            del key._secret


class GeneratedKeyTests(GuardTestCase):
    pass


def _make_generated_key_test(algorithm, length):
    def test(self):
        key = HmacKey.generate(algorithm)
        self.assertEqual(algorithm, key.algorithm)
        self.assertEqual(length, len(key.secret))
        token = sign_jwt({"exp": NOW + 300}, key, algorithm=algorithm)
        self.assertEqual(NOW + 300, verify(token, key, algorithms=[algorithm])["exp"])
    return test


for _algorithm, _length in (("HS256", 32), ("HS384", 48), ("HS512", 64)):
    setattr(GeneratedKeyTests, "test_generate_{}_key".format(_algorithm.lower()), _make_generated_key_test(_algorithm, _length))


class SignaturePrimitiveTests(GuardTestCase):
    def test_hs256_digest_size_is_32(self):
        self.assertEqual(32, digest_size("HS256"))

    def test_hs384_digest_size_is_48(self):
        self.assertEqual(48, digest_size("HS384"))

    def test_hs512_digest_size_is_64(self):
        self.assertEqual(64, digest_size("HS512"))

    def test_digest_size_rejects_unknown_algorithm(self):
        self.assertCode("KEY_INVALID", digest_size, "HS999")

    def test_truncated_signature_is_rejected(self):
        token = manual_token()
        parts = token.split(".")
        import base64
        raw = base64.urlsafe_b64decode((parts[2] + "=" * (-len(parts[2]) % 4)).encode("ascii"))[:-1]
        parts[2] = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
        self.assertVerifyCode("SIGNATURE_INVALID", ".".join(parts))

    def test_extended_signature_is_rejected(self):
        token = manual_token()
        self.assertVerifyCode("SIGNATURE_INVALID", token + "A")

    def test_flipped_signature_bit_is_rejected(self):
        token = manual_token()
        parts = token.split(".")
        replacement = "A" if parts[2][0] != "A" else "B"
        parts[2] = replacement + parts[2][1:]
        self.assertVerifyCode("SIGNATURE_INVALID", ".".join(parts))

    def test_payload_bit_flip_is_rejected(self):
        token = manual_token()
        parts = token.split(".")
        replacement = "A" if parts[1][0] != "A" else "B"
        parts[1] = replacement + parts[1][1:]
        self.assertVerifyCode("SIGNATURE_INVALID", ".".join(parts))


if __name__ == "__main__":
    unittest.main()
