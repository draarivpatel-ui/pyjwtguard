"""RFC 7515 and RFC 7797 interoperability vector tests."""

import base64
import unittest

from pyjwtguard import decode_unverified, verify_jwt

from _support import GuardTestCase, HS256_SECRET

RFC7515_TOKEN = (
    "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"
    "."
    "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt"
    "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
    "."
    "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
)
RFC7515_KEY_JWK_K = (
    "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75"
    "aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
)


def rfc_key():
    padding = "=" * (-len(RFC7515_KEY_JWK_K) % 4)
    return base64.urlsafe_b64decode((RFC7515_KEY_JWK_K + padding).encode("ascii"))


class Rfc7515HmacVectorTests(GuardTestCase):
    def test_appendix_a1_hmac_vector_verifies(self):
        claims = verify_jwt(
            RFC7515_TOKEN,
            rfc_key(),
            algorithms=["HS256"],
            now=1300819370,
        )
        self.assertEqual("joe", claims["iss"])
        self.assertEqual(1300819380, claims["exp"])
        self.assertIs(True, claims["http://example.com/is_root"])

    def test_appendix_a1_vector_header_decodes_exactly(self):
        decoded = decode_unverified(RFC7515_TOKEN)
        self.assertEqual("JWT", decoded.header["typ"])
        self.assertEqual("HS256", decoded.header["alg"])

    def test_appendix_a1_vector_signature_is_32_bytes(self):
        decoded = decode_unverified(RFC7515_TOKEN)
        self.assertEqual(32, decoded.signature_bytes)

    def test_appendix_a1_vector_rejects_wrong_key(self):
        self.assertCode(
            "SIGNATURE_INVALID",
            verify_jwt,
            RFC7515_TOKEN,
            HS256_SECRET,
            algorithms=["HS256"],
            now=1300819370,
        )

    def test_appendix_a1_vector_rejects_signature_mutation(self):
        parts = RFC7515_TOKEN.split(".")
        replacement = "A" if parts[2][0] != "A" else "B"
        parts[2] = replacement + parts[2][1:]
        self.assertCode(
            "SIGNATURE_INVALID",
            verify_jwt,
            ".".join(parts),
            rfc_key(),
            algorithms=["HS256"],
            now=1300819370,
        )

    def test_appendix_a1_vector_rejects_payload_mutation(self):
        parts = RFC7515_TOKEN.split(".")
        replacement = "A" if parts[1][0] != "A" else "B"
        parts[1] = replacement + parts[1][1:]
        self.assertCode(
            "SIGNATURE_INVALID",
            verify_jwt,
            ".".join(parts),
            rfc_key(),
            algorithms=["HS256"],
            now=1300819370,
        )

    def test_appendix_a1_vector_expires_at_exact_expiry(self):
        self.assertCode(
            "TOKEN_EXPIRED",
            verify_jwt,
            RFC7515_TOKEN,
            rfc_key(),
            algorithms=["HS256"],
            now=1300819380,
        )

    def test_appendix_a1_vector_leeway_accepts_exactly_inside_skew(self):
        claims = verify_jwt(
            RFC7515_TOKEN,
            rfc_key(),
            algorithms=["HS256"],
            now=1300819381,
            leeway=2,
        )
        self.assertEqual("joe", claims["iss"])


class Rfc7797ShapeTests(GuardTestCase):
    def test_rfc7797_detached_compact_example_shape_is_rejected(self):
        token = (
            "eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19"
            ".."
            "A5dxf2s96_n5FLueVuW1Z_vh161FwXZC4YLPff6dmDY"
        )
        self.assertCode(
            "MALFORMED_TOKEN",
            verify_jwt,
            token,
            HS256_SECRET,
            algorithms=["HS256"],
            now=1300819370,
            allow_unencoded_payload=True,
        )

    def test_rfc7797_header_vector_has_expected_shape(self):
        decoded_header = decode_unverified(
            "eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19"
            + ".{}."
            + "AA",
            allow_unencoded_payload=True,
        ).header
        self.assertEqual("HS256", decoded_header["alg"])
        self.assertIs(False, decoded_header["b64"])
        self.assertEqual(["b64"], decoded_header["crit"])


if __name__ == "__main__":
    unittest.main()
