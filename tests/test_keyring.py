"""Safe key rotation, keyring, resolver, and kid lookup tests."""

import unittest

from pyjwtguard import HmacKey, sign_jwt, verify_jwt

from _support import GuardTestCase, HS256_SECRET, NOW, manual_token, strong_secret, verify

KEY_A = HmacKey(strong_secret("HS256"), "HS256")
KEY_B = HmacKey(bytes(range(32)), "HS256")
KEY384 = HmacKey(strong_secret("HS384"), "HS384")


def rotated_token(kid, key=KEY_A):
    return sign_jwt({"exp": NOW + 300}, key, headers={"kid": kid})


class KeyringRotationTests(GuardTestCase):
    def test_first_rotation_key_is_selected_by_kid(self):
        token = rotated_token("key-a", KEY_A)
        claims = verify_jwt(token, keyring={"key-a": KEY_A, "key-b": KEY_B}, algorithms=["HS256"], now=NOW)
        self.assertEqual(NOW + 300, claims["exp"])

    def test_second_rotation_key_is_selected_by_kid(self):
        token = rotated_token("key-b", KEY_B)
        claims = verify_jwt(token, keyring={"key-a": KEY_A, "key-b": KEY_B}, algorithms=["HS256"], now=NOW)
        self.assertEqual(NOW + 300, claims["exp"])

    def test_old_key_fails_after_rotation_removes_it(self):
        token = rotated_token("key-a", KEY_A)
        self.assertCode(
            "KEY_NOT_FOUND",
            verify_jwt,
            token,
            keyring={"key-b": KEY_B},
            algorithms=["HS256"],
            now=NOW,
        )

    def test_missing_kid_fails_closed_with_keyring(self):
        token = sign_jwt({"exp": NOW + 300}, KEY_A)
        self.assertCode("KID_INVALID", verify_jwt, token, keyring={"key-a": KEY_A}, algorithms=["HS256"], now=NOW)

    def test_keyring_accepts_bound_hs384_key(self):
        token = sign_jwt({"exp": NOW + 300}, KEY384, algorithm="HS384", headers={"kid": "key-384"})
        claims = verify_jwt(token, keyring={"key-384": KEY384}, algorithms=["HS384"], now=NOW)
        self.assertEqual(NOW + 300, claims["exp"])

    def test_keyring_rejects_key_bound_to_wrong_algorithm(self):
        token = rotated_token("key-a", KEY_A)
        self.assertCode(
            "KEY_CONFUSION",
            verify_jwt,
            token,
            keyring={"key-a": KEY384},
            algorithms=["HS256"],
            now=NOW,
        )


class KeyringConfigurationTests(GuardTestCase):
    pass


_KEYRING_BAD = [
    ("empty", {}),
    ("list", []),
    ("string", "key"),
    ("raw_bytes_value", {"key-a": strong_secret("HS256")}),
    ("none_value", {"key-a": None}),
    ("path_key", {"../key-a": KEY_A}),
    ("empty_key", {"": KEY_A}),
    ("integer_key", {7: KEY_A}),
]


def _make_bad_keyring_test(label, keyring):
    def test(self):
        token = rotated_token("key-a", KEY_A)
        self.assertCode("CONFIG_INVALID", verify_jwt, token, keyring=keyring, algorithms=["HS256"], now=NOW)
    return test


for _label, _keyring in _KEYRING_BAD:
    setattr(KeyringConfigurationTests, "test_keyring_{}_is_rejected".format(_label), _make_bad_keyring_test(_label, _keyring))


class KeyResolverTests(GuardTestCase):
    def test_resolver_receives_exact_kid_and_returns_key(self):
        seen = []
        def resolver(kid):
            seen.append(kid)
            return KEY_A
        token = rotated_token("key-a", KEY_A)
        claims = verify_jwt(token, key_resolver=resolver, algorithms=["HS256"], now=NOW)
        self.assertEqual(NOW + 300, claims["exp"])
        self.assertEqual(["key-a"], seen)

    def test_resolver_keyerror_becomes_key_not_found(self):
        def resolver(kid):
            raise KeyError(kid)
        token = rotated_token("missing", KEY_A)
        self.assertCode("KEY_NOT_FOUND", verify_jwt, token, key_resolver=resolver, algorithms=["HS256"], now=NOW)

    def test_resolver_lookup_error_becomes_key_not_found(self):
        def resolver(kid):
            raise LookupError(kid)
        token = rotated_token("missing", KEY_A)
        self.assertCode("KEY_NOT_FOUND", verify_jwt, token, key_resolver=resolver, algorithms=["HS256"], now=NOW)

    def test_resolver_unexpected_exception_is_key_invalid(self):
        def resolver(kid):
            raise RuntimeError("database unavailable")
        token = rotated_token("key-a", KEY_A)
        self.assertCode("KEY_INVALID", verify_jwt, token, key_resolver=resolver, algorithms=["HS256"], now=NOW)

    def test_resolver_must_return_hmac_key(self):
        token = rotated_token("key-a", KEY_A)
        self.assertCode(
            "KEY_INVALID",
            verify_jwt,
            token,
            key_resolver=lambda kid: strong_secret("HS256"),
            algorithms=["HS256"],
            now=NOW,
        )

    def test_resolver_wrong_algorithm_binding_is_rejected(self):
        token = rotated_token("key-a", KEY_A)
        self.assertCode(
            "KEY_CONFUSION",
            verify_jwt,
            token,
            key_resolver=lambda kid: KEY384,
            algorithms=["HS256"],
            now=NOW,
        )

    def test_resolver_configuration_must_be_callable(self):
        token = rotated_token("key-a", KEY_A)
        self.assertCode("CONFIG_INVALID", verify_jwt, token, key_resolver="lookup", algorithms=["HS256"], now=NOW)

    def test_malicious_kid_is_rejected_before_resolver_is_called(self):
        seen = []
        def resolver(kid):
            seen.append(kid)
            return KEY_A
        token = manual_token(header={"alg": "HS256", "kid": "../secret"})
        self.assertCode("KID_INVALID", verify_jwt, token, key_resolver=resolver, algorithms=["HS256"], now=NOW)
        self.assertEqual([], seen)

    def test_resolver_is_not_called_for_disallowed_algorithm(self):
        seen = []
        def resolver(kid):
            seen.append(kid)
            return KEY_A
        token = manual_token(header={"alg": "HS384", "kid": "key-a"}, secret=strong_secret("HS384"), algorithm="HS384")
        self.assertCode("ALGORITHM_NOT_ALLOWED", verify_jwt, token, key_resolver=resolver, algorithms=["HS256"], now=NOW)
        self.assertEqual([], seen)


class KeySourceExclusivityTests(GuardTestCase):
    def test_key_and_keyring_together_are_rejected(self):
        token = rotated_token("key-a", KEY_A)
        self.assertCode(
            "CONFIG_INVALID",
            verify_jwt,
            token,
            KEY_A,
            keyring={"key-a": KEY_A},
            algorithms=["HS256"],
            now=NOW,
        )

    def test_key_and_resolver_together_are_rejected(self):
        token = rotated_token("key-a", KEY_A)
        self.assertCode(
            "CONFIG_INVALID",
            verify_jwt,
            token,
            KEY_A,
            key_resolver=lambda kid: KEY_A,
            algorithms=["HS256"],
            now=NOW,
        )

    def test_keyring_and_resolver_together_are_rejected(self):
        token = rotated_token("key-a", KEY_A)
        self.assertCode(
            "CONFIG_INVALID",
            verify_jwt,
            token,
            keyring={"key-a": KEY_A},
            key_resolver=lambda kid: KEY_A,
            algorithms=["HS256"],
            now=NOW,
        )

    def test_keyring_is_rejected_for_asymmetric_algorithm(self):
        token = manual_token(header={"alg": "RS256", "kid": "key-a"}, signature="AA")
        self.assertCode(
            "CONFIG_INVALID",
            verify_jwt,
            token,
            keyring={"key-a": KEY_A},
            algorithms=["RS256"],
            now=NOW,
        )

    def test_direct_hmac_key_does_not_require_kid(self):
        token = sign_jwt({"exp": NOW + 300}, KEY_A)
        self.assertEqual(NOW + 300, verify_jwt(token, KEY_A, algorithms=["HS256"], now=NOW)["exp"])


if __name__ == "__main__":
    unittest.main()
