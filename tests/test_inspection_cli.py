"""Unverified inspection API and command line behavior tests."""

import argparse
import contextlib
import io
import json
import unittest

import pyjwtguard
from pyjwtguard import decode_unverified, inspect_header, inspect_token, sign_jwt
from pyjwtguard.cli import build_parser, main

from _support import GuardTestCase, HS256_SECRET, NOW, manual_token, verify


class DecodeUnverifiedTests(GuardTestCase):
    def test_decode_unverified_decodes_bad_signature_without_trusting_it(self):
        token = manual_token()
        parts = token.split(".")
        parts[2] = "AA"
        decoded = decode_unverified(".".join(parts))
        self.assertFalse(decoded.verified)
        self.assertEqual(NOW + 300, decoded.claims["exp"])

    def test_decode_unverified_reports_algorithm(self):
        decoded = decode_unverified(manual_token())
        self.assertEqual("HS256", decoded.algorithm)

    def test_decode_unverified_reports_signature_size(self):
        decoded = decode_unverified(manual_token())
        self.assertEqual(32, decoded.signature_bytes)

    def test_decode_unverified_reports_segment_lengths(self):
        token = manual_token()
        decoded = decode_unverified(token)
        expected = tuple(len(part) for part in token.split("."))
        self.assertEqual(expected, decoded.segment_lengths)

    def test_decode_unverified_to_dict_marks_verified_false(self):
        report = decode_unverified(manual_token()).to_dict()
        self.assertIs(False, report["verified"])
        self.assertIn("segments", report)

    def test_decode_unverified_does_not_apply_temporal_claim_validation(self):
        token = manual_token(payload={"exp": 1})
        decoded = decode_unverified(token)
        self.assertEqual(1, decoded.claims["exp"])

    def test_decode_unverified_needs_no_key_or_allowlist(self):
        decoded = decode_unverified(manual_token())
        self.assertEqual("HS256", decoded.algorithm)

    def test_decode_unverified_rejects_dangerous_header_by_default(self):
        token = manual_token(header={"alg": "HS256", "jku": "https://evil.example"})
        self.assertCode("HEADER_FORBIDDEN", decode_unverified, token)

    def test_decode_unverified_can_report_remote_header_with_optin(self):
        token = manual_token(header={"alg": "HS256", "jku": "https://keys.example"})
        decoded = decode_unverified(token, allow_remote_headers=True)
        self.assertEqual("https://keys.example", decoded.header["jku"])

    def test_inspect_token_matches_decode_unverified(self):
        token = manual_token()
        self.assertEqual(decode_unverified(token).to_dict(), inspect_token(token).to_dict())

    def test_inspect_header_returns_header_only(self):
        token = manual_token(header={"alg": "HS256", "kid": "key-1"})
        header = inspect_header(token)
        self.assertEqual("key-1", header["kid"])

    def test_decode_unsafe_is_not_part_of_public_api(self):
        self.assertFalse(hasattr(pyjwtguard, "decode_unsafe"))


class SigningInspectionTests(GuardTestCase):
    def test_signing_unicode_claim_round_trips(self):
        token = sign_jwt({"exp": NOW + 300, "name": "café"}, HS256_SECRET)
        self.assertEqual("café", verify(token)["name"])

    def test_signing_generated_token_size_limit_is_enforced(self):
        self.assertCode(
            "TOKEN_TOO_LARGE",
            sign_jwt,
            {"exp": NOW + 300, "pad": "x" * 200},
            HS256_SECRET,
            max_token_size=80,
        )

    def test_signing_max_token_size_must_be_valid(self):
        self.assertCode("CONFIG_INVALID", sign_jwt, {"exp": NOW + 300}, HS256_SECRET, max_token_size=0)

    def test_headers_must_be_mapping(self):
        self.assertCode("CONFIG_INVALID", sign_jwt, {"exp": NOW + 300}, HS256_SECRET, headers=[("kid", "x")])

    def test_header_names_must_be_strings(self):
        self.assertCode("CONFIG_INVALID", sign_jwt, {"exp": NOW + 300}, HS256_SECRET, headers={7: "x"})

    def test_header_names_must_not_be_empty(self):
        self.assertCode("CONFIG_INVALID", sign_jwt, {"exp": NOW + 300}, HS256_SECRET, headers={"": "x"})

    def test_headers_cannot_override_alg(self):
        self.assertCode(
            "CONFIG_INVALID",
            sign_jwt,
            {"exp": NOW + 300},
            HS256_SECRET,
            headers={"alg": "HS384"},
        )

    def test_headers_may_repeat_same_alg(self):
        token = sign_jwt({"exp": NOW + 300}, HS256_SECRET, headers={"alg": "HS256"})
        self.assertEqual(NOW + 300, verify(token)["exp"])

    def test_typ_can_be_customized_for_explicit_typing(self):
        token = sign_jwt({"exp": NOW + 300}, HS256_SECRET, headers={"typ": "secevent+jwt"})
        self.assertEqual(NOW + 300, verify(token, expected_type="secevent+jwt")["exp"])

    def test_claims_must_be_mapping(self):
        self.assertCode("CONFIG_INVALID", sign_jwt, ["not", "claims"], HS256_SECRET)


class CliTests(GuardTestCase):
    def run_cli(self, argv):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = main(argv)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_cli_inspect_outputs_json_report(self):
        code, stdout, stderr = self.run_cli(["inspect", manual_token()])
        self.assertEqual(0, code)
        report = json.loads(stdout)
        self.assertIs(False, report["verified"])
        self.assertIn("Signature is not verified", report["note"])
        self.assertEqual("", stderr)

    def test_cli_inspect_rejects_bad_token(self):
        code, stdout, stderr = self.run_cli(["inspect", "bad"])
        self.assertEqual(3, code)
        self.assertEqual("", stdout)
        self.assertIn("MALFORMED_TOKEN", stderr)

    def test_cli_without_command_returns_usage_error(self):
        code, stdout, stderr = self.run_cli([])
        self.assertEqual(2, code)
        self.assertIn("usage:", stderr)

    def test_cli_max_token_size_is_enforced(self):
        code, stdout, stderr = self.run_cli(["inspect", manual_token(), "--max-token-size", "10"])
        self.assertEqual(3, code)
        self.assertIn("TOKEN_TOO_LARGE", stderr)

    def test_cli_remote_header_requires_optin(self):
        token = manual_token(header={"alg": "HS256", "jku": "https://keys.example"})
        code, stdout, stderr = self.run_cli(["inspect", token])
        self.assertEqual(3, code)
        self.assertIn("HEADER_FORBIDDEN", stderr)

    def test_cli_remote_header_optin_reports_token(self):
        token = manual_token(header={"alg": "HS256", "jku": "https://keys.example"})
        code, stdout, stderr = self.run_cli(["inspect", token, "--allow-remote-headers"])
        self.assertEqual(0, code)
        self.assertEqual("https://keys.example", json.loads(stdout)["header"]["jku"])

    def test_cli_parser_has_unencoded_payload_option(self):
        parser = build_parser()
        self.assertIsInstance(parser, argparse.ArgumentParser)
        code, stdout, stderr = self.run_cli([
            "inspect",
            sign_jwt({"exp": NOW + 300}, HS256_SECRET, allow_unencoded_payload=True),
            "--allow-unencoded-payload",
        ])
        self.assertEqual(0, code)
        self.assertTrue(json.loads(stdout)["unencoded_payload"])


if __name__ == "__main__":
    unittest.main()
