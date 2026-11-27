"""Strict JSON parser differential and duplicate key tests."""

import unittest

from pyjwtguard import decode_unverified, sign_jwt
from pyjwtguard.jsonparse import MAX_JSON_DEPTH

from _support import GuardTestCase, HS256_SECRET, NOW, b64, json_segment, manual_token, sign_segments, verify


def token_with_raw_segments(header_text, payload_text):
    return sign_segments(b64(header_text), b64(payload_text), HS256_SECRET, "HS256")


def valid_header_segment():
    return b64(b'{"alg":"HS256"}')


def nested_arrays(depth):
    nested = "1"
    for _ in range(depth):
        nested = "[" + nested + "]"
    return nested


class DuplicateJsonKeyTests(GuardTestCase):
    def test_duplicate_alg_in_header_is_rejected(self):
        token = token_with_raw_segments('{"alg":"HS256","alg":"none"}', '{"exp":1700000300}')
        self.assertVerifyCode("JSON_DUPLICATE_KEY", token)

    def test_duplicate_exp_in_payload_is_rejected_after_valid_signature(self):
        token = token_with_raw_segments('{"alg":"HS256"}', '{"exp":1700000300,"exp":1}')
        self.assertVerifyCode("JSON_DUPLICATE_KEY", token)

    def test_duplicate_key_using_unicode_escape_is_rejected(self):
        token = token_with_raw_segments('{"alg":"HS256","\\u0061lg":"RS256"}', '{"exp":1700000300}')
        self.assertVerifyCode("JSON_DUPLICATE_KEY", token)

    def test_duplicate_key_inside_header_extension_object_is_rejected(self):
        token = token_with_raw_segments('{"alg":"HS256","x":{"a":1,"a":2}}', '{"exp":1700000300}')
        self.assertVerifyCode("JSON_DUPLICATE_KEY", token)

    def test_duplicate_key_inside_payload_nested_object_is_rejected(self):
        token = token_with_raw_segments('{"alg":"HS256"}', '{"exp":1700000300,"x":{"a":1,"a":2}}')
        self.assertVerifyCode("JSON_DUPLICATE_KEY", token)

    def test_duplicate_key_inside_payload_array_object_is_rejected(self):
        token = token_with_raw_segments('{"alg":"HS256"}', '{"exp":1700000300,"x":[{"a":1,"a":2}]}')
        self.assertVerifyCode("JSON_DUPLICATE_KEY", token)

    def test_similar_but_distinct_unicode_keys_are_allowed(self):
        token = manual_token(payload={"exp": NOW + 300, "café": 1, "cafe": 2})
        self.assertEqual(1, verify(token)["café"])

    def test_decode_unverified_also_rejects_duplicate_keys(self):
        token = token_with_raw_segments('{"alg":"HS256"}', '{"exp":1700000300,"exp":1}')
        self.assertCode("JSON_DUPLICATE_KEY", decode_unverified, token)


class MalformedJsonTests(GuardTestCase):
    pass


_MALFORMED_TEXTS = [
    ("truncated_object", "{"),
    ("trailing_comma", '{"exp":1700000300,}'),
    ("trailing_data", '{"exp":1700000300} trailing'),
    ("single_quotes", "{'exp':1700000300}"),
    ("unquoted_key", '{exp:1700000300}'),
    ("bad_escape", '{"exp":"\\x"}'),
    ("unescaped_control", '{"exp":"a\x01b"}'),
    ("empty_object_then_garbage", '{}x'),
]


def _make_malformed_payload_test(name, text):
    def test(self):
        token = token_with_raw_segments('{"alg":"HS256"}', text)
        self.assertVerifyCode("JSON_INVALID", token)
    return test


for _name, _text in _MALFORMED_TEXTS:
    setattr(MalformedJsonTests, "test_payload_{}_is_rejected".format(_name), _make_malformed_payload_test(_name, _text))


def _make_malformed_header_test(name, text):
    def test(self):
        token = sign_segments(b64(text), b64('{"exp":1700000300}'), HS256_SECRET, "HS256")
        self.assertVerifyCode("JSON_INVALID", token)
    return test


for _name, _text in _MALFORMED_TEXTS[:5]:
    setattr(MalformedJsonTests, "test_header_{}_is_rejected".format(_name), _make_malformed_header_test(_name, _text))


class TopLevelJsonTypeTests(GuardTestCase):
    pass


_TOP_LEVELS = [
    ("array", "[]"),
    ("string", '"x"'),
    ("number", "1"),
    ("true", "true"),
    ("false", "false"),
    ("null", "null"),
]


def _make_payload_type_test(name, text):
    def test(self):
        token = token_with_raw_segments('{"alg":"HS256"}', text)
        self.assertVerifyCode("CLAIMS_INVALID", token)
    return test


def _make_header_type_test(name, text):
    def test(self):
        token = sign_segments(b64(text), b64('{"exp":1700000300}'), HS256_SECRET, "HS256")
        self.assertVerifyCode("HEADER_INVALID", token)
    return test


for _name, _text in _TOP_LEVELS:
    setattr(TopLevelJsonTypeTests, "test_payload_top_level_{}_is_rejected".format(_name), _make_payload_type_test(_name, _text))
    setattr(TopLevelJsonTypeTests, "test_header_top_level_{}_is_rejected".format(_name), _make_header_type_test(_name, _text))


class NonFiniteJsonTests(GuardTestCase):
    pass


_NONFINITE = [
    ("nan", "NaN"),
    ("infinity", "Infinity"),
    ("negative_infinity", "-Infinity"),
    ("overflow_exponent", "1e999"),
    ("negative_overflow_exponent", "-1e999"),
]


def _make_nonfinite_payload_test(name, literal):
    def test(self):
        token = token_with_raw_segments('{"alg":"HS256"}', '{"exp":1700000300,"x":' + literal + '}')
        self.assertVerifyCode("JSON_NONFINITE", token)
    return test


for _name, _literal in _NONFINITE:
    setattr(NonFiniteJsonTests, "test_payload_{}_is_rejected".format(_name), _make_nonfinite_payload_test(_name, _literal))


def _make_nonfinite_header_test(name, literal):
    def test(self):
        token = sign_segments(b64('{"alg":"HS256","x":' + literal + '}'), b64('{"exp":1700000300}'), HS256_SECRET, "HS256")
        self.assertVerifyCode("JSON_NONFINITE", token)
    return test


for _name, _literal in _NONFINITE[:3]:
    setattr(NonFiniteJsonTests, "test_header_{}_is_rejected".format(_name), _make_nonfinite_header_test(_name, _literal))


class Utf8AndDepthTests(GuardTestCase):
    def test_invalid_utf8_header_is_rejected(self):
        token = sign_segments(b64(b"\xff"), b64(b'{"exp":1700000300}'), HS256_SECRET, "HS256")
        self.assertVerifyCode("JSON_INVALID", token)

    def test_invalid_utf8_payload_is_rejected_after_valid_signature(self):
        token = sign_segments(valid_header_segment(), b64(b"\xff"), HS256_SECRET, "HS256")
        self.assertVerifyCode("JSON_INVALID", token)

    def test_valid_unicode_payload_is_accepted(self):
        token = manual_token(payload={"exp": NOW + 300, "name": "Aariv café"})
        self.assertEqual("Aariv café", verify(token)["name"])

    def test_deeply_nested_payload_json_is_rejected_safely(self):
        nested = "1"
        for _ in range(1200):
            nested = "[" + nested + "]"
        token = token_with_raw_segments('{"alg":"HS256"}', '{"exp":1700000300,"deep":' + nested + '}')
        self.assertVerifyCode("JSON_INVALID", token)

    def test_deeply_nested_header_json_is_rejected_safely(self):
        nested = "1"
        for _ in range(1200):
            nested = "[" + nested + "]"
        token = sign_segments(b64('{"alg":"HS256","deep":' + nested + '}'), b64('{"exp":1700000300}'), HS256_SECRET, "HS256")
        self.assertVerifyCode("JSON_INVALID", token)

    def test_payload_json_at_depth_cap_is_accepted(self):
        token = token_with_raw_segments(
            '{"alg":"HS256"}',
            '{"exp":1700000300,"deep":' + nested_arrays(MAX_JSON_DEPTH - 1) + '}',
        )
        self.assertIn("deep", verify(token))

    def test_payload_json_one_past_depth_cap_is_rejected(self):
        token = token_with_raw_segments(
            '{"alg":"HS256"}',
            '{"exp":1700000300,"deep":' + nested_arrays(MAX_JSON_DEPTH) + '}',
        )
        self.assertVerifyCode("JSON_INVALID", token)


class JsonExactnessTests(GuardTestCase):
    def test_issuer_comparison_does_not_normalize_unicode(self):
        token = manual_token(payload={"exp": NOW + 300, "iss": "café"})
        self.assertVerifyCode("ISSUER_MISMATCH", token, issuer="cafe\u0301")

    def test_exact_unicode_issuer_passes(self):
        token = manual_token(payload={"exp": NOW + 300, "iss": "café"})
        self.assertEqual("café", verify(token, issuer="café")["iss"])

    def test_json_key_order_does_not_affect_verification(self):
        payload = {"exp": NOW + 300, "b": 1, "a": 2}
        token = manual_token(payload=payload)
        self.assertEqual(2, verify(token)["a"])

    def test_signing_preserves_caller_claim_values(self):
        token = sign_jwt({"sub": "user", "exp": NOW + 300}, HS256_SECRET)
        decoded = decode_unverified(token)
        self.assertEqual("user", decoded.claims["sub"])

    def test_signing_rejects_nonstring_claim_name(self):
        self.assertCode("CONFIG_INVALID", sign_jwt, {7: "x", "exp": NOW + 300}, HS256_SECRET)

    def test_signing_rejects_empty_claim_name(self):
        self.assertCode("CONFIG_INVALID", sign_jwt, {"": "x", "exp": NOW + 300}, HS256_SECRET)

    def test_signing_rejects_nested_nonstring_object_key(self):
        claims = {"exp": NOW + 300, "nested": {1: "one"}}
        self.assertCode("CLAIM_INVALID", sign_jwt, claims, HS256_SECRET)

    def test_signing_rejects_circular_claims_typed(self):
        claims = {"exp": NOW + 300}
        claims["self"] = claims
        self.assertCode("CLAIM_INVALID", sign_jwt, claims, HS256_SECRET)

    def test_signing_rejects_lone_surrogate_in_claims_typed(self):
        claims = {"exp": NOW + 300, "bad": "\ud800"}
        self.assertCode("CLAIM_INVALID", sign_jwt, claims, HS256_SECRET)

    def test_verification_rejects_lone_surrogate_escape_in_claims(self):
        token = token_with_raw_segments('{"alg":"HS256"}', '{"exp":1700000300,"bad":"\\ud800"}')
        self.assertVerifyCode("JSON_INVALID", token)

    def test_valid_non_bmp_unicode_string_is_accepted(self):
        token = manual_token(payload={"exp": NOW + 300, "emoji": "\U0001f600"})
        self.assertEqual("\U0001f600", verify(token)["emoji"])


    def test_signing_rejects_excessively_nested_claims_typed(self):
        claims = {}
        current = claims
        for _ in range(1200):
            current["nested"] = {}
            current = current["nested"]
        self.assertCode("CLAIM_INVALID", sign_jwt, claims, HS256_SECRET)

    def test_signing_accepts_claims_at_depth_cap(self):
        claims = {"exp": NOW + 300}
        current = claims
        for _ in range(MAX_JSON_DEPTH - 1):
            current["nested"] = {}
            current = current["nested"]
        token = sign_jwt(claims, HS256_SECRET)
        self.assertIn("nested", decode_unverified(token).claims)

    def test_signing_rejects_claims_one_past_depth_cap(self):
        claims = {"exp": NOW + 300}
        current = claims
        for _ in range(MAX_JSON_DEPTH):
            current["nested"] = {}
            current = current["nested"]
        self.assertCode("CLAIM_INVALID", sign_jwt, claims, HS256_SECRET)


if __name__ == "__main__":
    unittest.main()
