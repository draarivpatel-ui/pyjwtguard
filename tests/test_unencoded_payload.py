"""RFC 7797 b64 false compact payload tests."""

import unittest

from pyjwtguard import decode_unverified, sign_jwt, verify_jwt

from _support import GuardTestCase, HS256_SECRET, NOW, b64, manual_token, sign_segments, verify


def unencoded_claims():
    return {"exp": NOW + 300, "iat": NOW, "sub": "user"}


def sign_unencoded(claims=None, **kwargs):
    if claims is None:
        claims = unencoded_claims()
    return sign_jwt(claims, HS256_SECRET, allow_unencoded_payload=True, **kwargs)


class UnencodedPayloadRoundTripTests(GuardTestCase):
    def test_unencoded_payload_round_trip_with_explicit_optin(self):
        token = sign_unencoded()
        claims = verify_jwt(
            token,
            HS256_SECRET,
            algorithms=["HS256"],
            now=NOW,
            allow_unencoded_payload=True,
        )
        self.assertEqual("user", claims["sub"])

    def test_unencoded_payload_is_rejected_by_default(self):
        token = sign_unencoded()
        self.assertVerifyCode("HEADER_INVALID", token)

    def test_unencoded_payload_is_visible_as_raw_json(self):
        token = sign_unencoded()
        payload_segment = token.split(".")[1]
        self.assertTrue(payload_segment.startswith('{"exp":'))
        self.assertIn('"sub":"user"', payload_segment)

    def test_unencoded_header_contains_b64_false_and_crit(self):
        token = sign_unencoded()
        header = decode_unverified(token, allow_unencoded_payload=True).header
        self.assertIs(False, header["b64"])
        self.assertIn("b64", header["crit"])

    def test_decode_unverified_reports_unencoded_shape(self):
        token = sign_unencoded()
        decoded = decode_unverified(token, allow_unencoded_payload=True)
        self.assertTrue(decoded.unencoded_payload)
        self.assertFalse(decoded.verified)
        self.assertEqual("user", decoded.claims["sub"])

    def test_decode_unverified_rejects_unencoded_payload_by_default(self):
        token = sign_unencoded()
        self.assertCode("HEADER_INVALID", decode_unverified, token)

    def test_unicode_claim_is_ascii_escaped_in_unencoded_payload(self):
        token = sign_unencoded({"exp": NOW + 300, "name": "café"})
        self.assertIn("caf\\u00e9", token.split(".")[1])
        claims = verify_jwt(token, HS256_SECRET, algorithms=["HS256"], now=NOW, allow_unencoded_payload=True)
        self.assertEqual("café", claims["name"])

    def test_space_inside_string_is_allowed(self):
        token = sign_unencoded({"exp": NOW + 300, "name": "a user"})
        claims = verify_jwt(token, HS256_SECRET, algorithms=["HS256"], now=NOW, allow_unencoded_payload=True)
        self.assertEqual("a user", claims["name"])

    def test_period_inside_string_is_rejected_at_signing(self):
        self.assertCode(
            "CLAIMS_INVALID",
            sign_jwt,
            {"exp": NOW + 300, "name": "a.user"},
            HS256_SECRET,
            allow_unencoded_payload=True,
        )

    def test_fractional_number_is_rejected_at_signing(self):
        self.assertCode(
            "CLAIMS_INVALID",
            sign_jwt,
            {"exp": NOW + 0.5},
            HS256_SECRET,
            allow_unencoded_payload=True,
        )

    def test_conflicting_b64_true_header_is_rejected(self):
        self.assertCode(
            "CONFIG_INVALID",
            sign_jwt,
            unencoded_claims(),
            HS256_SECRET,
            headers={"b64": True},
            allow_unencoded_payload=True,
        )

    def test_custom_critical_extension_can_accompany_b64(self):
        token = sign_unencoded(
            unencoded_claims(),
            headers={"custom": 1, "crit": ["custom"]},
            understood_critical_headers=["custom"],
        )
        claims = verify_jwt(
            token,
            HS256_SECRET,
            algorithms=["HS256"],
            now=NOW,
            allow_unencoded_payload=True,
            understood_critical_headers=["custom"],
        )
        self.assertEqual("user", claims["sub"])

    def test_tuple_crit_is_rejected_when_signing_unencoded(self):
        self.assertCode(
            "CONFIG_INVALID",
            sign_jwt,
            unencoded_claims(),
            HS256_SECRET,
            headers={"crit": ("custom",), "custom": 1},
            allow_unencoded_payload=True,
        )


class UnencodedPayloadAttackTests(GuardTestCase):
    def make_raw_token(self, payload_segment):
        header = b64(b'{"alg":"HS256","b64":false,"crit":["b64"]}')
        return sign_segments(header, payload_segment, HS256_SECRET, "HS256")

    def test_tampered_unencoded_payload_is_rejected(self):
        token = sign_unencoded()
        parts = token.split(".")
        parts[1] = parts[1].replace("user", "admn")
        self.assertCode(
            "SIGNATURE_INVALID",
            verify_jwt,
            ".".join(parts),
            HS256_SECRET,
            algorithms=["HS256"],
            now=NOW,
            allow_unencoded_payload=True,
        )

    def test_unencoded_payload_is_not_base64_decoded(self):
        payload = '{"exp":1700000300,"sub":"user"}'
        token = self.make_raw_token(payload)
        claims = verify_jwt(token, HS256_SECRET, algorithms=["HS256"], now=NOW, allow_unencoded_payload=True)
        self.assertEqual("user", claims["sub"])

    def test_raw_unicode_payload_is_rejected(self):
        header = b64(b'{"alg":"HS256","b64":false,"crit":["b64"]}')
        token = header + '.' + '{"exp":1700000300,"name":"café"}' + '.AA'
        self.assertCode(
            "CLAIMS_INVALID",
            verify_jwt,
            token,
            HS256_SECRET,
            algorithms=["HS256"],
            now=NOW,
            allow_unencoded_payload=True,
        )

    def test_raw_control_character_payload_is_rejected(self):
        token = self.make_raw_token('{"exp":1700000300,"x":"a\x01b"}')
        self.assertCode(
            "CLAIMS_INVALID",
            verify_jwt,
            token,
            HS256_SECRET,
            algorithms=["HS256"],
            now=NOW,
            allow_unencoded_payload=True,
        )

    def test_raw_period_in_payload_breaks_compact_structure(self):
        token = self.make_raw_token('{"exp":1700000300,"x":"a')
        token = token + '.b"}'
        self.assertCode(
            "MALFORMED_TOKEN",
            verify_jwt,
            token,
            HS256_SECRET,
            algorithms=["HS256"],
            now=NOW,
            allow_unencoded_payload=True,
        )

    def test_detached_payload_shape_is_rejected(self):
        header = b64(b'{"alg":"HS256","b64":false,"crit":["b64"]}')
        token = header + ".." + b64(b"sig")
        self.assertCode(
            "MALFORMED_TOKEN",
            verify_jwt,
            token,
            HS256_SECRET,
            algorithms=["HS256"],
            now=NOW,
            allow_unencoded_payload=True,
        )

    def test_empty_unencoded_payload_is_rejected(self):
        header = b64(b'{"alg":"HS256","b64":false,"crit":["b64"]}')
        token = header + ".." + b64(b"sig")
        self.assertCode("MALFORMED_TOKEN", decode_unverified, token, allow_unencoded_payload=True)

    def test_missing_crit_is_rejected_for_raw_token(self):
        header = b64(b'{"alg":"HS256","b64":false}')
        token = sign_segments(header, '{"exp":1700000300}', HS256_SECRET, "HS256")
        self.assertCode(
            "CRIT_INVALID",
            verify_jwt,
            token,
            HS256_SECRET,
            algorithms=["HS256"],
            now=NOW,
            allow_unencoded_payload=True,
        )

    def test_encoded_payload_with_b64_true_still_works(self):
        token = manual_token(header={"alg": "HS256", "b64": True})
        self.assertEqual(NOW + 300, verify(token, allow_unencoded_payload=True)["exp"])

    def test_allow_unencoded_payload_must_be_boolean_on_verify(self):
        self.assertVerifyCode("CONFIG_INVALID", sign_unencoded(), allow_unencoded_payload=1)

    def test_allow_unencoded_payload_must_be_boolean_on_sign(self):
        self.assertCode(
            "CONFIG_INVALID",
            sign_jwt,
            unencoded_claims(),
            HS256_SECRET,
            allow_unencoded_payload=1,
        )


if __name__ == "__main__":
    unittest.main()
