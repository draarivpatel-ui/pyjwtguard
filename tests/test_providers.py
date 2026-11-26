"""AlgorithmProvider signer and verifier integration tests."""

import base64
import hashlib
import unittest

from pyjwtguard import decode_unverified, sign_jwt, verify_jwt

from _support import GuardTestCase, HS256_SECRET, NOW, json_segment, manual_token, verify


def pseudo_signature(signing_input):
    return hashlib.sha256(b"provider" + signing_input).digest()


def b64_signature(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


class StaticVerifier:
    def __init__(self, algorithms=("RS256",), result=True):
        self.algorithms = set(algorithms)
        self.result = result
        self.calls = []

    def supports(self, algorithm):
        return algorithm in self.algorithms

    def verify(self, algorithm, signing_input, signature, header):
        self.calls.append((algorithm, signing_input, signature, dict(header)))
        if not self.result:
            return False
        return signature == pseudo_signature(signing_input)


class StaticSigner:
    def __init__(self, algorithms=("RS256",)):
        self.algorithms = set(algorithms)
        self.calls = []

    def supports(self, algorithm):
        return algorithm in self.algorithms

    def sign(self, algorithm, signing_input, header):
        self.calls.append((algorithm, signing_input, dict(header)))
        return pseudo_signature(signing_input)


def provider_token(payload=None):
    if payload is None:
        payload = {"exp": NOW + 300}
    header_segment = json_segment({"alg": "RS256", "typ": "JWT"})
    payload_segment = json_segment(payload)
    signing_input = (header_segment + "." + payload_segment).encode("ascii")
    return signing_input.decode("ascii") + "." + b64_signature(pseudo_signature(signing_input))


class ProviderVerificationTests(GuardTestCase):
    def test_provider_verifies_rs256_token(self):
        token = provider_token()
        claims = verify_jwt(token, algorithms=["RS256"], providers=[StaticVerifier()], now=NOW)
        self.assertEqual(NOW + 300, claims["exp"])

    def test_provider_receives_exact_signing_input_and_header_copy(self):
        token = provider_token()
        provider = StaticVerifier()
        verify_jwt(token, algorithms=["RS256"], providers=[provider], now=NOW)
        self.assertEqual(1, len(provider.calls))
        algorithm, signing_input, signature, header = provider.calls[0]
        self.assertEqual("RS256", algorithm)
        self.assertEqual(".".join(token.split(".")[:2]).encode("ascii"), signing_input)
        self.assertEqual(pseudo_signature(signing_input), signature)
        self.assertEqual("RS256", header["alg"])

    def test_provider_header_mutation_does_not_change_verified_header(self):
        class MutatingVerifier(StaticVerifier):
            def verify(self, algorithm, signing_input, signature, header):
                header["alg"] = "HS256"
                return True
        token = provider_token()
        claims = verify_jwt(token, algorithms=["RS256"], providers=[MutatingVerifier()], now=NOW)
        self.assertEqual(NOW + 300, claims["exp"])
        self.assertEqual("RS256", decode_unverified(token).header["alg"])

    def test_provider_false_result_is_signature_invalid(self):
        token = provider_token()
        self.assertCode(
            "SIGNATURE_INVALID",
            verify_jwt,
            token,
            algorithms=["RS256"],
            providers=[StaticVerifier(result=False)],
            now=NOW,
        )

    def test_missing_provider_is_unsupported(self):
        token = provider_token()
        self.assertCode("ALGORITHM_UNSUPPORTED", verify_jwt, token, algorithms=["RS256"], now=NOW)

    def test_provider_that_does_not_support_algorithm_is_unsupported(self):
        token = provider_token()
        self.assertCode(
            "ALGORITHM_UNSUPPORTED",
            verify_jwt,
            token,
            algorithms=["RS256"],
            providers=[StaticVerifier(algorithms=("ES256",))],
            now=NOW,
        )

    def test_second_provider_can_verify_after_first_returns_false(self):
        token = provider_token()
        providers = [StaticVerifier(result=False), StaticVerifier(result=True)]
        claims = verify_jwt(token, algorithms=["RS256"], providers=providers, now=NOW)
        self.assertEqual(NOW + 300, claims["exp"])

    def test_all_provider_false_results_are_signature_invalid(self):
        token = provider_token()
        providers = [StaticVerifier(result=False), StaticVerifier(result=False)]
        self.assertCode("SIGNATURE_INVALID", verify_jwt, token, algorithms=["RS256"], providers=providers, now=NOW)

    def test_hmac_uses_builtin_key_even_when_provider_is_registered(self):
        token = manual_token()
        provider = StaticVerifier(algorithms=("HS256",), result=False)
        claims = verify_jwt(token, HS256_SECRET, algorithms=["HS256"], providers=[provider], now=NOW)
        self.assertEqual(NOW + 300, claims["exp"])

    def test_hmac_without_key_is_not_satisfied_by_provider(self):
        token = manual_token()
        provider = StaticVerifier(algorithms=("HS256",), result=True)
        self.assertCode("KEY_INVALID", verify_jwt, token, algorithms=["HS256"], providers=[provider], now=NOW)


class ProviderFailureTests(GuardTestCase):
    def test_nonboolean_supports_result_is_rejected(self):
        class BadSupports:
            def supports(self, algorithm):
                return 1
            def verify(self, algorithm, signing_input, signature, header):
                return True
        self.assertCode(
            "VERIFIER_INVALID",
            verify_jwt,
            provider_token(),
            algorithms=["RS256"],
            providers=[BadSupports()],
            now=NOW,
        )

    def test_supports_exception_is_rejected(self):
        class BadSupports:
            def supports(self, algorithm):
                raise RuntimeError("kms unavailable")
            def verify(self, algorithm, signing_input, signature, header):
                return True
        self.assertCode(
            "VERIFIER_INVALID",
            verify_jwt,
            provider_token(),
            algorithms=["RS256"],
            providers=[BadSupports()],
            now=NOW,
        )

    def test_nonboolean_verify_result_is_rejected(self):
        class BadVerify(StaticVerifier):
            def verify(self, algorithm, signing_input, signature, header):
                return 1
        self.assertCode(
            "VERIFIER_INVALID",
            verify_jwt,
            provider_token(),
            algorithms=["RS256"],
            providers=[BadVerify()],
            now=NOW,
        )

    def test_verify_exception_is_rejected(self):
        class BadVerify(StaticVerifier):
            def verify(self, algorithm, signing_input, signature, header):
                raise RuntimeError("kms unavailable")
        self.assertCode(
            "VERIFIER_INVALID",
            verify_jwt,
            provider_token(),
            algorithms=["RS256"],
            providers=[BadVerify()],
            now=NOW,
        )

    def test_provider_missing_verify_method_is_configuration_error(self):
        class SupportsOnly:
            def supports(self, algorithm):
                return True
        self.assertCode(
            "CONFIG_INVALID",
            verify_jwt,
            provider_token(),
            algorithms=["RS256"],
            providers=[SupportsOnly()],
            now=NOW,
        )

    def test_providers_string_configuration_is_rejected(self):
        self.assertCode(
            "CONFIG_INVALID",
            verify_jwt,
            provider_token(),
            algorithms=["RS256"],
            providers="provider",
            now=NOW,
        )


class ProviderSigningTests(GuardTestCase):
    def test_provider_signs_and_matching_provider_verifies(self):
        signer = StaticSigner()
        token = sign_jwt({"exp": NOW + 300}, provider=signer, algorithm="RS256")
        claims = verify_jwt(token, algorithms=["RS256"], providers=[StaticVerifier()], now=NOW)
        self.assertEqual(NOW + 300, claims["exp"])

    def test_signing_provider_receives_exact_input_and_header_copy(self):
        signer = StaticSigner()
        token = sign_jwt({"exp": NOW + 300}, provider=signer, algorithm="RS256")
        algorithm, signing_input, header = signer.calls[0]
        self.assertEqual("RS256", algorithm)
        self.assertEqual(".".join(token.split(".")[:2]).encode("ascii"), signing_input)
        self.assertEqual("RS256", header["alg"])

    def test_signing_provider_header_mutation_does_not_change_token(self):
        class MutatingSigner(StaticSigner):
            def sign(self, algorithm, signing_input, header):
                header["alg"] = "HS256"
                return pseudo_signature(signing_input)
        token = sign_jwt({"exp": NOW + 300}, provider=MutatingSigner(), algorithm="RS256")
        self.assertEqual("RS256", decode_unverified(token).header["alg"])

    def test_key_and_provider_together_are_rejected(self):
        self.assertCode(
            "CONFIG_INVALID",
            sign_jwt,
            {"exp": NOW + 300},
            HS256_SECRET,
            provider=StaticSigner(),
            algorithm="RS256",
        )

    def test_provider_for_builtin_hmac_is_rejected(self):
        self.assertCode(
            "CONFIG_INVALID",
            sign_jwt,
            {"exp": NOW + 300},
            provider=StaticSigner(algorithms=("HS256",)),
            algorithm="HS256",
        )

    def test_unsupported_signing_algorithm_is_rejected(self):
        self.assertCode(
            "ALGORITHM_UNSUPPORTED",
            sign_jwt,
            {"exp": NOW + 300},
            provider=StaticSigner(algorithms=("ES256",)),
            algorithm="RS256",
        )

    def test_signing_provider_missing_sign_method_is_configuration_error(self):
        class VerifyOnly(StaticVerifier):
            pass
        self.assertCode(
            "CONFIG_INVALID",
            sign_jwt,
            {"exp": NOW + 300},
            provider=VerifyOnly(),
            algorithm="RS256",
        )

    def test_signing_provider_nonboolean_supports_is_rejected(self):
        class BadSupports(StaticSigner):
            def supports(self, algorithm):
                return 1
        self.assertCode(
            "SIGNER_INVALID",
            sign_jwt,
            {"exp": NOW + 300},
            provider=BadSupports(),
            algorithm="RS256",
        )

    def test_signing_provider_supports_exception_is_rejected(self):
        class BadSupports(StaticSigner):
            def supports(self, algorithm):
                raise RuntimeError("kms unavailable")
        self.assertCode(
            "SIGNER_INVALID",
            sign_jwt,
            {"exp": NOW + 300},
            provider=BadSupports(),
            algorithm="RS256",
        )

    def test_signing_provider_exception_is_rejected(self):
        class BadSign(StaticSigner):
            def sign(self, algorithm, signing_input, header):
                raise RuntimeError("kms unavailable")
        self.assertCode(
            "SIGNER_INVALID",
            sign_jwt,
            {"exp": NOW + 300},
            provider=BadSign(),
            algorithm="RS256",
        )

    def test_signing_provider_must_return_bytes(self):
        class BadSign(StaticSigner):
            def sign(self, algorithm, signing_input, header):
                return "signature"
        self.assertCode(
            "SIGNER_INVALID",
            sign_jwt,
            {"exp": NOW + 300},
            provider=BadSign(),
            algorithm="RS256",
        )

    def test_signing_provider_empty_signature_is_rejected(self):
        class BadSign(StaticSigner):
            def sign(self, algorithm, signing_input, header):
                return b""
        self.assertCode(
            "SIGNER_INVALID",
            sign_jwt,
            {"exp": NOW + 300},
            provider=BadSign(),
            algorithm="RS256",
        )

    def test_bytearray_signature_is_accepted(self):
        class ByteArraySigner(StaticSigner):
            def sign(self, algorithm, signing_input, header):
                return bytearray(pseudo_signature(signing_input))
        token = sign_jwt({"exp": NOW + 300}, provider=ByteArraySigner(), algorithm="RS256")
        self.assertEqual(NOW + 300, verify_jwt(token, algorithms=["RS256"], providers=[StaticVerifier()], now=NOW)["exp"])

    def test_none_algorithm_never_reaches_provider(self):
        signer = StaticSigner(algorithms=("none",))
        self.assertCode("ALGORITHM_NONE", sign_jwt, {"exp": NOW + 300}, provider=signer, algorithm="none")


if __name__ == "__main__":
    unittest.main()
