"""Algorithm allowlist, none-algorithm, and confusion boundary tests."""

import base64
import hashlib
import hmac
import unittest

from pyjwtguard import sign_jwt, verify_jwt

from _support import (
    GuardTestCase,
    HS256_SECRET,
    HS384_SECRET,
    NOW,
    b64,
    manual_token,
    sign_segments,
    verify,
)


def lowercase_alg_token():
    header = b64(b'{"alg":"hs256"}')
    payload = b64(b'{"exp":1700000300}')
    signing_input = (header + "." + payload).encode("ascii")
    signature = hmac.new(HS256_SECRET.encode("utf-8"), signing_input, hashlib.sha256).digest()
    encoded = base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")
    return signing_input.decode("ascii") + "." + encoded


class ExplicitAllowlistTests(GuardTestCase):
    def test_missing_algorithms_is_rejected(self):
        self.assertCode("CONFIG_INVALID", verify_jwt, manual_token(), HS256_SECRET, now=NOW)

    def test_none_algorithms_is_rejected(self):
        self.assertCode("CONFIG_INVALID", verify_jwt, manual_token(), HS256_SECRET, algorithms=None, now=NOW)

    def test_string_algorithms_is_rejected(self):
        self.assertCode("CONFIG_INVALID", verify_jwt, manual_token(), HS256_SECRET, algorithms="HS256", now=NOW)

    def test_bytes_algorithms_is_rejected(self):
        self.assertCode("CONFIG_INVALID", verify_jwt, manual_token(), HS256_SECRET, algorithms=b"HS256", now=NOW)

    def test_empty_allowlist_is_rejected(self):
        self.assertCode("CONFIG_INVALID", verify_jwt, manual_token(), HS256_SECRET, algorithms=[], now=NOW)

    def test_non_sequence_allowlist_is_rejected(self):
        self.assertCode("CONFIG_INVALID", verify_jwt, manual_token(), HS256_SECRET, algorithms=42, now=NOW)

    def test_tuple_allowlist_is_accepted(self):
        claims = verify(manual_token(), algorithms=("HS256",))
        self.assertEqual(NOW + 300, claims["exp"])

    def test_list_allowlist_is_accepted(self):
        claims = verify(manual_token(), algorithms=["HS384", "HS256"])
        self.assertEqual(NOW + 300, claims["exp"])

    def test_allowlist_is_exact_and_case_sensitive(self):
        token = lowercase_alg_token()
        self.assertVerifyCode("ALGORITHM_NOT_ALLOWED", token)

    def test_disallowed_valid_hs384_token_is_rejected(self):
        token = manual_token(header={"alg": "HS384"}, secret=HS384_SECRET, algorithm="HS384")
        self.assertVerifyCode("ALGORITHM_NOT_ALLOWED", token, HS384_SECRET, algorithms=["HS256"])

    def test_valid_hs384_token_passes_when_allowlisted(self):
        token = manual_token(header={"alg": "HS384"}, secret=HS384_SECRET, algorithm="HS384")
        claims = verify(token, HS384_SECRET, algorithms=["HS384"])
        self.assertEqual(NOW + 300, claims["exp"])

    def test_allowlist_does_not_permit_unknown_header_algorithm(self):
        token = manual_token(header={"alg": "HS999"}, signature="AA")
        self.assertCode(
            "ALGORITHM_UNSUPPORTED",
            verify_jwt,
            token,
            None,
            algorithms=["HS999"],
            now=NOW,
        )


class AllowlistEntryMatrixTests(GuardTestCase):
    pass


_BAD_ALLOWLISTS = [
    ("empty_name", [""]),
    ("whitespace_name", [" HS256"]),
    ("trailing_whitespace", ["HS256 "]),
    ("integer", [42]),
    ("none_value", [None]),
    ("bool_value", [True]),
    ("duplicate", ["HS256", "HS256"]),
]


def _make_bad_allowlist_test(name, algorithms):
    def test(self):
        self.assertCode("CONFIG_INVALID", verify_jwt, manual_token(), HS256_SECRET, algorithms=algorithms, now=NOW)
    return test


for _name, _algorithms in _BAD_ALLOWLISTS:
    setattr(AllowlistEntryMatrixTests, "test_bad_allowlist_{}".format(_name), _make_bad_allowlist_test(_name, _algorithms))


class NoneAlgorithmTests(GuardTestCase):
    pass


_NONE_SPELLINGS = [
    "none",
    "None",
    "NONE",
    "nOnE",
    "NoNe",
    "nONE",
    " none",
    "none ",
]


def _make_none_verify_test(spelling):
    def test(self):
        token = manual_token(header={"alg": spelling}, signature="")
        self.assertVerifyCode("ALGORITHM_NONE", token, algorithms=["HS256"])
    return test


def _make_none_allowlist_test(spelling):
    def test(self):
        token = manual_token()
        self.assertCode("CONFIG_INVALID", verify_jwt, token, HS256_SECRET, algorithms=[spelling], now=NOW)
    return test


def _make_none_sign_test(spelling):
    def test(self):
        expected = "CONFIG_INVALID" if spelling != spelling.strip() else "ALGORITHM_NONE"
        self.assertCode(expected, sign_jwt, {"exp": NOW + 300}, HS256_SECRET, algorithm=spelling)
    return test


for _spelling in _NONE_SPELLINGS:
    _clean = "".join(ch if ch.isalnum() else "space" for ch in _spelling)
    setattr(NoneAlgorithmTests, "test_alg_{}_is_rejected".format(_clean), _make_none_verify_test(_spelling))
    setattr(NoneAlgorithmTests, "test_alg_{}_cannot_be_allowlisted".format(_clean), _make_none_allowlist_test(_spelling))
    setattr(NoneAlgorithmTests, "test_alg_{}_cannot_be_signed".format(_clean), _make_none_sign_test(_spelling))


class HeaderAlgorithmShapeTests(GuardTestCase):
    pass


_BAD_ALGORITHMS = [
    ("missing", None),
    ("empty", ""),
    ("bool", True),
    ("integer", 7),
    ("list", ["HS256"]),
    ("object", {"value": "HS256"}),
]


def _make_bad_algorithm_header_test(name, value):
    def test(self):
        header = {"typ": "JWT"} if value is None and name == "missing" else {"alg": value}
        token = manual_token(header=header, signature="AA")
        self.assertVerifyCode("HEADER_INVALID", token)
    return test


for _name, _value in _BAD_ALGORITHMS:
    setattr(HeaderAlgorithmShapeTests, "test_header_alg_{}_is_rejected".format(_name), _make_bad_algorithm_header_test(_name, _value))


class AlgorithmKeyBoundaryTests(GuardTestCase):
    def test_rs256_without_provider_is_unsupported(self):
        token = manual_token(header={"alg": "RS256"}, signature="AA")
        self.assertCode("ALGORITHM_UNSUPPORTED", verify_jwt, token, None, algorithms=["RS256"], now=NOW)

    def test_hmac_key_passed_for_rs256_is_configuration_error(self):
        token = manual_token(header={"alg": "RS256"}, signature="AA")
        self.assertCode("CONFIG_INVALID", verify_jwt, token, HS256_SECRET, algorithms=["RS256"], now=NOW)

    def test_hmac_token_without_key_is_rejected(self):
        self.assertCode("KEY_INVALID", verify_jwt, manual_token(), None, algorithms=["HS256"], now=NOW)

    def test_sign_rs256_without_provider_is_unsupported(self):
        self.assertCode("ALGORITHM_UNSUPPORTED", sign_jwt, {"exp": NOW + 300}, HS256_SECRET, algorithm="RS256")

    def test_sign_rejects_empty_algorithm(self):
        self.assertCode("CONFIG_INVALID", sign_jwt, {"exp": NOW + 300}, HS256_SECRET, algorithm="")

    def test_sign_rejects_nonstring_algorithm(self):
        self.assertCode("CONFIG_INVALID", sign_jwt, {"exp": NOW + 300}, HS256_SECRET, algorithm=42)

    def test_sign_rejects_outer_whitespace_algorithm(self):
        self.assertCode("CONFIG_INVALID", sign_jwt, {"exp": NOW + 300}, HS256_SECRET, algorithm=" HS256")

    def test_header_alg_outer_whitespace_is_not_allowlisted(self):
        token = manual_token(header={"alg": " HS256"}, signature="AA")
        self.assertVerifyCode("ALGORITHM_NOT_ALLOWED", token)

    def test_header_alg_trailing_whitespace_is_not_allowlisted(self):
        token = manual_token(header={"alg": "HS256 "}, signature="AA")
        self.assertVerifyCode("ALGORITHM_NOT_ALLOWED", token)

    def test_algorithm_allowlist_is_matched_before_claim_parsing(self):
        token = manual_token(header={"alg": "HS384"}, payload="not-base64", secret=HS384_SECRET, algorithm="HS384")
        self.assertVerifyCode("ALGORITHM_NOT_ALLOWED", token, HS384_SECRET, algorithms=["HS256"])


if __name__ == "__main__":
    unittest.main()
