"""Strict base64url and compact serialization tests."""

import unittest

from pyjwtguard import decode_unverified, verify_jwt
from pyjwtguard.base64url import b64url_decode, b64url_encode

from _support import GuardTestCase, HS256_SECRET, NOW, b64, manual_token, sign_segments, verify


class Base64UrlPrimitiveTests(GuardTestCase):
    def test_empty_bytes_encode_to_empty_text(self):
        self.assertEqual("", b64url_encode(b""))

    def test_single_zero_byte_encoding(self):
        self.assertEqual("AA", b64url_encode(b"\x00"))

    def test_two_byte_encoding(self):
        self.assertEqual("AAA", b64url_encode(b"\x00\x00"))

    def test_three_byte_encoding(self):
        self.assertEqual("AAAA", b64url_encode(b"\x00\x00\x00"))

    def test_urlsafe_minus_is_used(self):
        self.assertEqual("-A", b64url_encode(b"\xf8"))

    def test_urlsafe_underscore_is_used(self):
        self.assertEqual("_w", b64url_encode(b"\xff"))

    def test_encode_accepts_bytearray(self):
        self.assertEqual("AQID", b64url_encode(bytearray([1, 2, 3])))

    def test_encode_accepts_memoryview(self):
        self.assertEqual("AQID", b64url_encode(memoryview(b"\x01\x02\x03")))

    def test_encode_rejects_text(self):
        with self.assertRaises(TypeError):
            b64url_encode("abc")

    def test_round_trip_binary_data(self):
        raw = bytes(range(256))
        self.assertEqual(raw, b64url_decode(b64url_encode(raw)))

    def test_decode_rejects_non_text(self):
        self.assertCode("BASE64_INVALID", b64url_decode, b"AA")

    def test_decode_rejects_impossible_length_modulo_one(self):
        self.assertCode("BASE64_INVALID", b64url_decode, "A")

    def test_decode_rejects_impossible_five_character_length(self):
        self.assertCode("BASE64_INVALID", b64url_decode, "AAAAA")

    def test_decode_rejects_noncanonical_trailing_bits_two_characters(self):
        self.assertCode("BASE64_NONCANONICAL", b64url_decode, "AB")

    def test_decode_rejects_noncanonical_trailing_bits_three_characters(self):
        self.assertCode("BASE64_NONCANONICAL", b64url_decode, "AAB")

    def test_decode_accepts_canonical_two_character_segment(self):
        self.assertEqual(b"\x00", b64url_decode("AA"))

    def test_decode_accepts_canonical_three_character_segment(self):
        self.assertEqual(b"\x00\x00", b64url_decode("AAA"))


class Base64UrlRejectMatrixTests(GuardTestCase):
    pass


_INVALID_SEGMENTS = [
    ("padding", "AA="),
    ("double_padding", "AA=="),
    ("plus", "AA+A"),
    ("slash", "AA/A"),
    ("space", "AA A"),
    ("tab", "AA\tA"),
    ("newline", "AA\nA"),
    ("carriage_return", "AA\rA"),
    ("nul", "AA\x00A"),
    ("unicode", "AAéA"),
    ("equals_inside", "A=AA"),
    ("equals_only", "===="),
    ("comma", "AA,A"),
    ("period", "AA.A"),
    ("percent", "AA%A"),
]


def _make_invalid_segment_test(name, segment):
    def test(self):
        self.assertIn(
            self.assertCode("BASE64_INVALID", b64url_decode, segment).code,
            {"BASE64_INVALID", "BASE64_NONCANONICAL"},
        )
    test.__name__ = "test_invalid_segment_{}".format(name)
    return test


for _name, _segment in _INVALID_SEGMENTS:
    setattr(Base64UrlRejectMatrixTests, "test_invalid_segment_{}".format(_name), _make_invalid_segment_test(_name, _segment))


class TokenStructureTests(GuardTestCase):
    def test_token_must_be_text(self):
        self.assertCode("MALFORMED_TOKEN", verify_jwt, b"a.b.c", HS256_SECRET, algorithms=["HS256"], now=NOW)

    def test_empty_token_is_rejected(self):
        self.assertVerifyCode("MALFORMED_TOKEN", "")

    def test_single_segment_is_rejected(self):
        self.assertVerifyCode("MALFORMED_TOKEN", "abc")

    def test_two_segments_are_rejected(self):
        self.assertVerifyCode("MALFORMED_TOKEN", "abc.def")

    def test_four_segments_are_rejected(self):
        self.assertVerifyCode("MALFORMED_TOKEN", "a.b.c.d")

    def test_empty_header_is_rejected(self):
        self.assertVerifyCode("MALFORMED_TOKEN", ".e30.sig")

    def test_empty_payload_is_rejected(self):
        self.assertVerifyCode("MALFORMED_TOKEN", "e30..sig")

    def test_empty_signature_is_rejected_for_hs256(self):
        token = manual_token(signature="")
        self.assertVerifyCode("SIGNATURE_INVALID", token)

    def test_oversized_token_is_rejected_before_decoding(self):
        token = manual_token(payload={"exp": NOW + 300, "pad": "x" * 300})
        self.assertVerifyCode("TOKEN_TOO_LARGE", token, max_token_size=80)

    def test_max_token_size_must_be_integer(self):
        self.assertVerifyCode("CONFIG_INVALID", manual_token(), max_token_size="8192")

    def test_max_token_size_must_not_be_boolean(self):
        self.assertVerifyCode("CONFIG_INVALID", manual_token(), max_token_size=True)

    def test_max_token_size_must_be_positive(self):
        self.assertVerifyCode("CONFIG_INVALID", manual_token(), max_token_size=0)

    def test_noncanonical_header_encoding_is_rejected(self):
        payload = b64(b'{"exp":1700000300}')
        header = b64(b'{"alg":"HS256"}') + "AB"
        token = header + "." + payload + ".AA"
        self.assertVerifyCode("BASE64_NONCANONICAL", token)

    def test_noncanonical_payload_encoding_is_rejected_after_valid_signature(self):
        header = b64(b'{"alg":"HS256"}')
        payload = b64(b'{"exp":1700000300}')
        mutated = payload + "AB"
        token = sign_segments(header, mutated, HS256_SECRET, "HS256")
        self.assertVerifyCode("BASE64_NONCANONICAL", token)

    def test_noncanonical_signature_encoding_is_rejected(self):
        token = manual_token()
        parts = token.split(".")
        parts[2] = parts[2][:-1] + "B"
        self.assertVerifyCode("BASE64_NONCANONICAL", ".".join(parts))

    def test_decode_unverified_is_structurally_strict(self):
        token = manual_token(signature="AA")
        decoded = decode_unverified(token)
        self.assertFalse(decoded.verified)
        self.assertEqual(1, decoded.signature_bytes)


if __name__ == "__main__":
    unittest.main()
