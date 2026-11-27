"""Strict registered claim validation tests."""

import unittest

from pyjwtguard import MAX_NUMERIC_DATE, MIN_NUMERIC_DATE, sign_jwt

from _support import GuardTestCase, HS256_SECRET, NOW, manual_token, verify


def claims_payload(**overrides):
    payload = {
        "exp": NOW + 300,
        "nbf": NOW - 10,
        "iat": NOW,
        "iss": "issuer-a",
        "aud": "api-a",
        "sub": "subject-a",
        "jti": "id-a",
    }
    payload.update(overrides)
    return payload


def token_with(overrides=None):
    payload = claims_payload()
    if overrides:
        payload.update(overrides)
    return manual_token(payload=payload)


class ExpirationTests(GuardTestCase):
    def test_future_expiration_passes(self):
        self.assertEqual(NOW + 300, verify(token_with({"exp": NOW + 300}))["exp"])

    def test_expiration_at_now_is_rejected(self):
        self.assertVerifyCode("TOKEN_EXPIRED", token_with({"exp": NOW}))

    def test_expiration_before_now_is_rejected(self):
        self.assertVerifyCode("TOKEN_EXPIRED", token_with({"exp": NOW - 1}))

    def test_leeway_permits_recent_expiration(self):
        token = token_with({"exp": NOW - 5})
        self.assertEqual(NOW - 5, verify(token, leeway=6)["exp"])

    def test_leeway_expiration_boundary_is_rejected(self):
        token = token_with({"exp": NOW - 5})
        self.assertVerifyCode("TOKEN_EXPIRED", token, leeway=5)

    def test_fractional_future_expiration_passes(self):
        token = token_with({"exp": NOW + 0.5})
        self.assertEqual(NOW + 0.5, verify(token)["exp"])

    def test_missing_exp_is_rejected_by_default(self):
        payload = claims_payload()
        del payload["exp"]
        self.assertVerifyCode("CLAIM_MISSING", manual_token(payload=payload))

    def test_missing_exp_passes_when_not_required(self):
        payload = claims_payload()
        del payload["exp"]
        claims = verify(manual_token(payload=payload), require_exp=False)
        self.assertNotIn("exp", claims)


class NotBeforeTests(GuardTestCase):
    def test_past_not_before_passes(self):
        self.assertEqual(NOW - 10, verify(token_with({"nbf": NOW - 10}))["nbf"])

    def test_not_before_at_now_passes(self):
        self.assertEqual(NOW, verify(token_with({"nbf": NOW}))["nbf"])

    def test_future_not_before_is_rejected(self):
        self.assertVerifyCode("TOKEN_NOT_YET_VALID", token_with({"nbf": NOW + 1}))

    def test_leeway_permits_slightly_future_not_before(self):
        token = token_with({"nbf": NOW + 5})
        self.assertEqual(NOW + 5, verify(token, leeway=5)["nbf"])

    def test_missing_nbf_passes_by_default(self):
        payload = claims_payload()
        del payload["nbf"]
        self.assertNotIn("nbf", verify(manual_token(payload=payload)))

    def test_missing_nbf_is_rejected_when_required(self):
        payload = claims_payload()
        del payload["nbf"]
        self.assertVerifyCode("CLAIM_MISSING", manual_token(payload=payload), require_nbf=True)


class IssuedAtTests(GuardTestCase):
    def test_current_iat_passes(self):
        self.assertEqual(NOW, verify(token_with({"iat": NOW}))["iat"])

    def test_future_iat_is_rejected(self):
        self.assertVerifyCode("TOKEN_ISSUED_IN_FUTURE", token_with({"iat": NOW + 1}))

    def test_leeway_permits_slightly_future_iat(self):
        token = token_with({"iat": NOW + 5})
        self.assertEqual(NOW + 5, verify(token, leeway=5)["iat"])

    def test_missing_iat_passes_by_default(self):
        payload = claims_payload()
        del payload["iat"]
        self.assertNotIn("iat", verify(manual_token(payload=payload)))

    def test_missing_iat_is_rejected_when_required(self):
        payload = claims_payload()
        del payload["iat"]
        self.assertVerifyCode("CLAIM_MISSING", manual_token(payload=payload), require_iat=True)


class NumericDateMatrixTests(GuardTestCase):
    pass


_NUMERIC_BAD_VALUES = [
    ("bool_true", True),
    ("bool_false", False),
    ("string", "1700000000"),
    ("none", None),
    ("array", [NOW]),
    ("object", {"value": NOW}),
    ("huge_int", 10 ** 100),
    ("huge_negative_int", -(10 ** 100)),
    ("above_maximum", MAX_NUMERIC_DATE + 1),
    ("below_minimum", MIN_NUMERIC_DATE - 1),
]


def _make_numeric_bad_test(claim, label, value):
    def test(self):
        token = token_with({claim: value})
        self.assertVerifyCode("CLAIM_INVALID", token)
    return test


for _claim in ("exp", "nbf", "iat"):
    for _label, _value in _NUMERIC_BAD_VALUES:
        setattr(
            NumericDateMatrixTests,
            "test_{}_{}_is_rejected".format(_claim, _label),
            _make_numeric_bad_test(_claim, _label, _value),
        )


class TemporalConfigurationTests(GuardTestCase):
    pass


_BAD_LEEWAY = [
    ("string", "5"),
    ("bool", True),
    ("negative", -1),
    ("nan", float("nan")),
    ("infinity", float("inf")),
]


def _make_bad_leeway_test(label, value):
    def test(self):
        self.assertVerifyCode("CONFIG_INVALID", token_with({}), leeway=value)
    return test


for _label, _value in _BAD_LEEWAY:
    setattr(TemporalConfigurationTests, "test_leeway_{}_is_rejected".format(_label), _make_bad_leeway_test(_label, _value))


_BAD_NOW = [
    ("string", "now"),
    ("bool", True),
    ("nan", float("nan")),
    ("infinity", float("inf")),
]


def _make_bad_now_test(label, value):
    def test(self):
        self.assertVerifyCode("CONFIG_INVALID", token_with({}), now=value)
    return test


for _label, _value in _BAD_NOW:
    setattr(TemporalConfigurationTests, "test_now_{}_is_rejected".format(_label), _make_bad_now_test(_label, _value))


class ClockTests(GuardTestCase):
    def test_callable_clock_is_used(self):
        token = token_with({"exp": 110, "iat": 90, "nbf": 90})
        self.assertEqual(110, verify(token, now=lambda: 100)["exp"])

    def test_failing_callable_clock_is_configuration_error(self):
        def broken():
            raise RuntimeError("clock failure")
        self.assertVerifyCode("CONFIG_INVALID", token_with({}), now=broken)

    def test_nonfinite_callable_clock_is_configuration_error(self):
        self.assertVerifyCode("CONFIG_INVALID", token_with({}), now=lambda: float("nan"))


class RequiredFlagTests(GuardTestCase):
    pass


for _flag in ("require_exp", "require_iat", "require_nbf"):
    def _make_flag_test(flag):
        def test(self):
            self.assertVerifyCode("CONFIG_INVALID", token_with({}), **{flag: 1})
        return test
    setattr(RequiredFlagTests, "test_{}_must_be_boolean".format(_flag), _make_flag_test(_flag))


class MaxAgeTests(GuardTestCase):
    def test_max_age_fails_closed_when_iat_is_missing(self):
        payload = claims_payload()
        del payload["iat"]
        self.assertVerifyCode("CLAIM_MISSING", manual_token(payload=payload), max_age=60)

    def test_fresh_token_passes_max_age(self):
        token = token_with({"iat": NOW - 30})
        self.assertEqual(NOW - 30, verify(token, max_age=60)["iat"])

    def test_exact_max_age_boundary_passes(self):
        token = token_with({"iat": NOW - 60})
        self.assertEqual(NOW - 60, verify(token, max_age=60)["iat"])

    def test_token_older_than_max_age_is_rejected(self):
        token = token_with({"iat": NOW - 61})
        self.assertVerifyCode("TOKEN_TOO_OLD", token, max_age=60)

    def test_leeway_extends_max_age(self):
        token = token_with({"iat": NOW - 65})
        self.assertEqual(NOW - 65, verify(token, max_age=60, leeway=5)["iat"])

    def test_future_iat_is_rejected_with_max_age(self):
        token = token_with({"iat": NOW + 1})
        self.assertVerifyCode("TOKEN_ISSUED_IN_FUTURE", token, max_age=60)


class MaxAgeConfigurationTests(GuardTestCase):
    pass


_BAD_MAX_AGE = [
    ("zero", 0),
    ("negative", -1),
    ("string", "60"),
    ("bool", True),
    ("nan", float("nan")),
    ("infinity", float("inf")),
]


def _make_bad_max_age_test(label, value):
    def test(self):
        self.assertVerifyCode("CONFIG_INVALID", token_with({}), max_age=value)
    return test


for _label, _value in _BAD_MAX_AGE:
    setattr(MaxAgeConfigurationTests, "test_max_age_{}_is_rejected".format(_label), _make_bad_max_age_test(_label, _value))


class IssuerTests(GuardTestCase):
    def test_exact_issuer_passes(self):
        self.assertEqual("issuer-a", verify(token_with({}), issuer="issuer-a")["iss"])

    def test_wrong_issuer_is_rejected(self):
        self.assertVerifyCode("ISSUER_MISMATCH", token_with({}), issuer="issuer-b")

    def test_missing_issuer_is_rejected_when_expected(self):
        payload = claims_payload()
        del payload["iss"]
        self.assertVerifyCode("CLAIM_MISSING", manual_token(payload=payload), issuer="issuer-a")

    def test_missing_issuer_passes_when_not_expected(self):
        payload = claims_payload()
        del payload["iss"]
        self.assertNotIn("iss", verify(manual_token(payload=payload)))

    def test_empty_issuer_configuration_is_rejected(self):
        self.assertVerifyCode("CONFIG_INVALID", token_with({}), issuer="")

    def test_nonstring_issuer_configuration_is_rejected(self):
        self.assertVerifyCode("CONFIG_INVALID", token_with({}), issuer=7)


class IssuerShapeMatrixTests(GuardTestCase):
    pass


def _make_string_claim_shape_test(claim, label, value):
    def test(self):
        self.assertVerifyCode("CLAIM_INVALID", token_with({claim: value}))
    return test


_STRING_BAD_VALUES = [
    ("empty", ""),
    ("integer", 7),
    ("bool", True),
    ("none", None),
    ("array", ["x"]),
    ("object", {"x": 1}),
]

for _claim in ("iss", "sub", "jti"):
    for _label, _value in _STRING_BAD_VALUES:
        setattr(
            IssuerShapeMatrixTests,
            "test_{}_{}_is_rejected".format(_claim, _label),
            _make_string_claim_shape_test(_claim, _label, _value),
        )


class AudienceTests(GuardTestCase):
    def test_string_audience_exact_match_passes(self):
        self.assertEqual("api-a", verify(token_with({}), audience="api-a")["aud"])

    def test_array_audience_intersection_passes(self):
        token = token_with({"aud": ["api-a", "api-b"]})
        self.assertEqual(["api-a", "api-b"], verify(token, audience="api-b")["aud"])

    def test_multiple_expected_audiences_allow_one_intersection(self):
        token = token_with({"aud": ["api-a", "api-b"]})
        self.assertEqual(["api-a", "api-b"], verify(token, audience=["other", "api-a"])["aud"])

    def test_wrong_audience_is_rejected(self):
        self.assertVerifyCode("AUDIENCE_MISMATCH", token_with({}), audience="api-b")

    def test_missing_audience_is_rejected_when_expected(self):
        payload = claims_payload()
        del payload["aud"]
        self.assertVerifyCode("CLAIM_MISSING", manual_token(payload=payload), audience="api-a")

    def test_missing_audience_passes_when_not_expected(self):
        payload = claims_payload()
        del payload["aud"]
        self.assertNotIn("aud", verify(manual_token(payload=payload)))


class AudienceShapeMatrixTests(GuardTestCase):
    pass


_AUD_BAD_VALUES = [
    ("empty_string", ""),
    ("empty_array", []),
    ("integer", 7),
    ("bool", True),
    ("none", None),
    ("object", {"aud": "api"}),
    ("integer_entry", [7]),
    ("empty_entry", [""]),
    ("duplicate_entries", ["api-a", "api-a"]),
]


def _make_audience_shape_test(label, value):
    def test(self):
        self.assertVerifyCode("CLAIM_INVALID", token_with({"aud": value}))
    return test


for _label, _value in _AUD_BAD_VALUES:
    setattr(AudienceShapeMatrixTests, "test_aud_{}_is_rejected".format(_label), _make_audience_shape_test(_label, _value))


class AudienceConfigurationTests(GuardTestCase):
    pass


_AUD_CONFIG_BAD = [
    ("empty_string", ""),
    ("empty_sequence", []),
    ("integer", 7),
    ("integer_entry", [7]),
    ("empty_entry", [""]),
    ("duplicates", ["api-a", "api-a"]),
]


def _make_audience_config_test(label, value):
    def test(self):
        self.assertVerifyCode("CONFIG_INVALID", token_with({}), audience=value)
    return test


for _label, _value in _AUD_CONFIG_BAD:
    setattr(AudienceConfigurationTests, "test_expected_audience_{}_is_rejected".format(_label), _make_audience_config_test(_label, _value))


class SubjectAndIdTests(GuardTestCase):
    def test_exact_subject_passes(self):
        self.assertEqual("subject-a", verify(token_with({}), subject="subject-a")["sub"])

    def test_wrong_subject_is_rejected(self):
        self.assertVerifyCode("SUBJECT_MISMATCH", token_with({}), subject="subject-b")

    def test_missing_subject_is_rejected_when_expected(self):
        payload = claims_payload()
        del payload["sub"]
        self.assertVerifyCode("CLAIM_MISSING", manual_token(payload=payload), subject="subject-a")

    def test_exact_jwt_id_passes(self):
        self.assertEqual("id-a", verify(token_with({}), jti="id-a")["jti"])

    def test_wrong_jwt_id_is_rejected(self):
        self.assertVerifyCode("JWT_ID_MISMATCH", token_with({}), jti="id-b")

    def test_missing_jwt_id_is_rejected_when_expected(self):
        payload = claims_payload()
        del payload["jti"]
        self.assertVerifyCode("CLAIM_MISSING", manual_token(payload=payload), jti="id-a")


class RequiredClaimsTests(GuardTestCase):
    def test_custom_required_claim_passes_when_present(self):
        token = token_with({"scope": "read"})
        self.assertEqual("read", verify(token, required_claims=["scope"])["scope"])

    def test_custom_required_claim_fails_closed_when_missing(self):
        self.assertVerifyCode("CLAIM_MISSING", token_with({}), required_claims=["scope"])

    def test_required_claim_rejects_none_and_empty_values(self):
        for value in (None, "", [], {}):
            with self.subTest(value=value):
                self.assertVerifyCode(
                    "CLAIM_INVALID",
                    token_with({"tenant": value}),
                    required_claims=["tenant"],
                )

    def test_required_claim_accepts_false_zero_and_nonempty_values(self):
        for value in (False, 0, "tenant-a", ["tenant-a"], {"id": "tenant-a"}):
            with self.subTest(value=value):
                claims = verify(token_with({"tenant": value}), required_claims=["tenant"])
                self.assertEqual(value, claims["tenant"])

    def test_required_claims_can_require_registered_claims(self):
        payload = claims_payload()
        del payload["sub"]
        self.assertVerifyCode("CLAIM_MISSING", manual_token(payload=payload), required_claims=["sub"])

    def test_required_claims_string_configuration_is_rejected(self):
        self.assertVerifyCode("CONFIG_INVALID", token_with({}), required_claims="scope")

    def test_required_claims_duplicate_configuration_is_rejected(self):
        self.assertVerifyCode("CONFIG_INVALID", token_with({}), required_claims=["scope", "scope"])


class SigningClaimShapeTests(GuardTestCase):
    def test_signing_rejects_boolean_expiration(self):
        self.assertCode("CLAIM_INVALID", sign_jwt, {"exp": True}, HS256_SECRET)

    def test_signing_rejects_huge_expiration(self):
        self.assertCode("CLAIM_INVALID", sign_jwt, {"exp": 10 ** 100}, HS256_SECRET)

    def test_signing_rejects_invalid_audience(self):
        self.assertCode("CLAIM_INVALID", sign_jwt, {"exp": NOW + 10, "aud": []}, HS256_SECRET)

    def test_signing_rejects_nonfinite_claim_number(self):
        self.assertCode("CLAIM_INVALID", sign_jwt, {"exp": NOW + 10, "custom": float("nan")}, HS256_SECRET)

    def test_signing_rejects_nonserializable_claim_value(self):
        self.assertCode("CLAIM_INVALID", sign_jwt, {"exp": NOW + 10, "custom": object()}, HS256_SECRET)


if __name__ == "__main__":
    unittest.main()
