"""JOSE header hardening, critical extension, typing, and kid tests."""

import unittest

from pyjwtguard import sign_jwt

from _support import GuardTestCase, HS256_SECRET, NOW, manual_token, verify


class RemoteHeaderDefaultTests(GuardTestCase):
    pass


_REMOTE_HEADERS = [
    ("jku", "https://keys.example/jwks.json"),
    ("x5u", "https://keys.example/cert.pem"),
    ("jwk", {"kty": "RSA", "n": "abc", "e": "AQAB"}),
    ("x5c", ["MIIB"] ),
]


def _make_remote_reject_test(name, value):
    def test(self):
        token = manual_token(header={"alg": "HS256", name: value})
        self.assertVerifyCode("HEADER_FORBIDDEN", token)
    return test


def _make_remote_optin_test(name, value):
    def test(self):
        token = manual_token(header={"alg": "HS256", name: value})
        claims = verify(token, allow_remote_headers=True)
        self.assertEqual(NOW + 300, claims["exp"])
    return test


for _name, _value in _REMOTE_HEADERS:
    setattr(RemoteHeaderDefaultTests, "test_{}_is_rejected_by_default".format(_name), _make_remote_reject_test(_name, _value))
    setattr(RemoteHeaderDefaultTests, "test_{}_is_ignored_when_explicitly_allowed".format(_name), _make_remote_optin_test(_name, _value))


class RemoteHeaderShapeTests(GuardTestCase):
    pass


_REMOTE_SHAPES = [
    ("jku_empty", {"jku": ""}),
    ("jku_integer", {"jku": 7}),
    ("jku_control", {"jku": "https://x\x01"}),
    ("x5u_empty", {"x5u": ""}),
    ("x5u_bool", {"x5u": True}),
    ("jwk_array", {"jwk": []}),
    ("x5c_empty", {"x5c": []}),
    ("x5c_integer_entry", {"x5c": [7]}),
]


def _make_remote_shape_test(name, extra):
    def test(self):
        header = {"alg": "HS256"}
        header.update(extra)
        token = manual_token(header=header)
        self.assertVerifyCode("HEADER_INVALID", token, allow_remote_headers=True)
    return test


for _name, _extra in _REMOTE_SHAPES:
    setattr(RemoteHeaderShapeTests, "test_{}_is_rejected".format(_name), _make_remote_shape_test(_name, _extra))


class SigningRemoteHeaderTests(GuardTestCase):
    def test_signing_rejects_remote_headers_by_default(self):
        self.assertCode(
            "HEADER_FORBIDDEN",
            sign_jwt,
            {"exp": NOW + 300},
            HS256_SECRET,
            headers={"jku": "https://keys.example/jwks.json"},
        )

    def test_signing_can_emit_remote_headers_with_explicit_optin(self):
        token = sign_jwt(
            {"exp": NOW + 300},
            HS256_SECRET,
            headers={"jku": "https://keys.example/jwks.json"},
            allow_remote_headers=True,
        )
        self.assertEqual(NOW + 300, verify(token, allow_remote_headers=True)["exp"])


class CriticalHeaderShapeTests(GuardTestCase):
    pass


_CRIT_SHAPES = [
    ("string", "custom", "crit must be array"),
    ("empty", [], "crit empty"),
    ("duplicate", ["custom", "custom"], "crit duplicate"),
    ("integer_entry", [7], "crit integer"),
    ("empty_entry", [""], "crit empty entry"),
    ("missing_header", ["missing"], "crit missing"),
]


def _make_crit_shape_test(name, crit, label):
    def test(self):
        token = manual_token(header={"alg": "HS256", "crit": crit, "custom": True})
        expected = "CRIT_INVALID"
        self.assertVerifyCode(expected, token)
    return test


for _name, _crit, _label in _CRIT_SHAPES:
    setattr(CriticalHeaderShapeTests, "test_crit_{}_is_rejected".format(_name), _make_crit_shape_test(_name, _crit, _label))


class CriticalHeaderSemanticsTests(GuardTestCase):
    def test_unknown_critical_header_is_rejected(self):
        token = manual_token(header={"alg": "HS256", "crit": ["custom"], "custom": True})
        self.assertVerifyCode("CRIT_UNKNOWN", token)

    def test_understood_critical_header_is_accepted(self):
        token = manual_token(header={"alg": "HS256", "crit": ["custom"], "custom": True})
        claims = verify(token, understood_critical_headers=["custom"])
        self.assertEqual(NOW + 300, claims["exp"])

    def test_understood_critical_header_must_be_present(self):
        token = manual_token(header={"alg": "HS256", "crit": ["custom"]})
        self.assertVerifyCode("CRIT_INVALID", token, understood_critical_headers=["custom"])

    def test_understood_critical_header_configuration_must_be_sequence(self):
        token = manual_token(header={"alg": "HS256", "crit": ["custom"], "custom": True})
        self.assertVerifyCode("CONFIG_INVALID", token, understood_critical_headers="custom")

    def test_understood_critical_header_configuration_rejects_duplicates(self):
        token = manual_token(header={"alg": "HS256", "crit": ["custom"], "custom": True})
        self.assertVerifyCode("CONFIG_INVALID", token, understood_critical_headers=["custom", "custom"])

    def test_uncritical_private_header_is_allowed(self):
        token = manual_token(header={"alg": "HS256", "custom": {"value": 1}})
        self.assertEqual(NOW + 300, verify(token)["exp"])


class CriticalRegisteredMatrixTests(GuardTestCase):
    pass


_REGISTERED_CRIT = [
    "alg",
    "crit",
    "kid",
    "typ",
    "cty",
    "jku",
    "jwk",
    "x5u",
    "x5c",
    "x5t",
    "x5t#S256",
    "TYP",
]


def _make_registered_crit_test(name):
    def test(self):
        header = {
            "alg": "HS256",
            "crit": [name],
            "kid": "key-1",
            "typ": "JWT",
            "cty": "JWT",
            "jku": "https://keys.example/jwks.json",
            "jwk": {"kty": "RSA"},
            "x5u": "https://keys.example/cert.pem",
            "x5c": ["MIIB"],
            "x5t": "thumb",
            "x5t#S256": "thumb256",
            "TYP": "JWT",
        }
        token = manual_token(header=header)
        self.assertVerifyCode("CRIT_INVALID", token, allow_remote_headers=True)
    return test


for _name in _REGISTERED_CRIT:
    _clean = _name.replace("#", "hash").lower()
    setattr(CriticalRegisteredMatrixTests, "test_crit_registered_{}_is_rejected".format(_clean), _make_registered_crit_test(_name))


class KeyIdValidationTests(GuardTestCase):
    pass


_BAD_KIDS = [
    ("integer", 7),
    ("empty", ""),
    ("too_long", "k" * 257),
    ("leading_space", " key"),
    ("trailing_space", "key "),
    ("newline", "key\n1"),
    ("nul", "key\x001"),
    ("forward_slash", "../keys/a"),
    ("backslash", "..\\keys\\a"),
    ("dotdot", "key..1"),
    ("encoded_dot", "%2e%2e"),
    ("encoded_slash", "a%2fb"),
    ("encoded_backslash", "a%5cb"),
    ("double_encoded_dot", "%252e%252e"),
    ("encoded_nul", "a%00b"),
    ("single_quote", "a'b"),
    ("double_quote", 'a"b'),
    ("semicolon", "a;b"),
    ("backtick", "a`b"),
    ("sql_comment", "a--b"),
    ("c_comment_open", "a/*b"),
    ("c_comment_close", "a*/b"),
    ("invisible", "a\u200db"),
]


def _make_bad_kid_test(name, kid):
    def test(self):
        token = manual_token(header={"alg": "HS256", "kid": kid})
        self.assertVerifyCode("KID_INVALID", token)
    return test


for _name, _kid in _BAD_KIDS:
    setattr(KeyIdValidationTests, "test_kid_{}_is_rejected".format(_name), _make_bad_kid_test(_name, _kid))


class KeyIdValidTests(GuardTestCase):
    def test_simple_kid_is_accepted(self):
        token = manual_token(header={"alg": "HS256", "kid": "key-2026-01"})
        self.assertEqual(NOW + 300, verify(token)["exp"])

    def test_unicode_kid_is_accepted_when_printable(self):
        token = manual_token(header={"alg": "HS256", "kid": "cle-été-1"})
        self.assertEqual(NOW + 300, verify(token)["exp"])

    def test_max_length_kid_is_accepted(self):
        token = manual_token(header={"alg": "HS256", "kid": "k" * 256})
        self.assertEqual(NOW + 300, verify(token)["exp"])


class HeaderTypingTests(GuardTestCase):
    pass


_BAD_HEADER_TEXT = [
    ("typ_integer", "typ", 7),
    ("typ_empty", "typ", ""),
    ("typ_control", "typ", "JW\x01T"),
    ("cty_integer", "cty", 7),
    ("cty_empty", "cty", ""),
    ("cty_control", "cty", "JW\x01T"),
]


def _make_bad_header_text_test(test_name, header_name, value):
    def test(self):
        token = manual_token(header={"alg": "HS256", header_name: value})
        self.assertVerifyCode("HEADER_INVALID", token)
    return test


for _test_name, _header_name, _value in _BAD_HEADER_TEXT:
    setattr(HeaderTypingTests, "test_{}_is_rejected".format(_test_name), _make_bad_header_text_test(_test_name, _header_name, _value))


class ExpectedTypeTests(GuardTestCase):
    def test_expected_type_passes_exact_match(self):
        token = manual_token(header={"alg": "HS256", "typ": "JWT"})
        self.assertEqual(NOW + 300, verify(token, expected_type="JWT")["exp"])

    def test_expected_type_rejects_mismatch(self):
        token = manual_token(header={"alg": "HS256", "typ": "JWT"})
        self.assertVerifyCode("TYPE_MISMATCH", token, expected_type="secevent+jwt")

    def test_expected_type_rejects_missing_typ(self):
        token = manual_token(header={"alg": "HS256"})
        self.assertVerifyCode("TYPE_MISMATCH", token, expected_type="JWT")

    def test_expected_type_is_case_sensitive(self):
        token = manual_token(header={"alg": "HS256", "typ": "jwt"})
        self.assertVerifyCode("TYPE_MISMATCH", token, expected_type="JWT")

    def test_expected_type_configuration_must_be_string(self):
        self.assertVerifyCode("CONFIG_INVALID", manual_token(), expected_type=7)


class B64HeaderPolicyTests(GuardTestCase):
    def test_b64_false_is_rejected_by_default(self):
        token = manual_token(header={"alg": "HS256", "b64": False, "crit": ["b64"]})
        self.assertVerifyCode("HEADER_INVALID", token)

    def test_b64_nonboolean_is_rejected(self):
        token = manual_token(header={"alg": "HS256", "b64": "false", "crit": ["b64"]})
        self.assertVerifyCode("HEADER_INVALID", token, allow_unencoded_payload=True)

    def test_b64_true_with_crit_b64_is_rejected(self):
        token = manual_token(header={"alg": "HS256", "b64": True, "crit": ["b64"]})
        self.assertVerifyCode("CRIT_INVALID", token, allow_unencoded_payload=True)

    def test_b64_false_without_crit_is_rejected_when_enabled(self):
        token = manual_token(header={"alg": "HS256", "b64": False})
        self.assertVerifyCode("CRIT_INVALID", token, allow_unencoded_payload=True)


if __name__ == "__main__":
    unittest.main()
