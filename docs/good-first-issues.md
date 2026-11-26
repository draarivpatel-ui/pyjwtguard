# Good first issues

Fifteen modular starter tasks for new contributors. Each is scoped to one file or one focused behavior. Every task must preserve the zero runtime dependency rule and Python 3.9 compatibility.

1. **Add RFC 7518 HMAC vectors** in `tests/test_rfc_vectors.py` for HS384 and HS512, including one altered signature for each.
2. **Add a base64url bit-flip matrix** in `tests/test_base64url.py` that checks every unused trailing pad bit position for length modulo 2 and modulo 3 segments.
3. **Add a JSON duplicate-key matrix** in `tests/test_json_security.py` covering nested objects three levels deep and objects inside arrays.
4. **Add CLI tests for empty standard input behavior** in `tests/test_inspection_cli.py`, then decide whether the CLI should reject standard input explicitly or support it behind a documented flag.
5. **Document a complete KMS adapter pattern** in `README.md` without adding a dependency, including how key rotation and `kid` ownership are enforced.
6. **Add provider conformance test helpers** in a new `tests/provider_contract.py` that downstream adapter authors can copy into their own test suites.
7. **Add timestamp boundary tests** in `tests/test_claims.py` for the exact minimum and maximum supported numeric dates.
8. **Add keyring mutation tests** in `tests/test_keyring.py` proving that changing a keyring after token creation does not alter already verified claims.
9. **Add a benchmark script** under `scripts/` using only stdlib `timeit` for HS256 verification throughput, with clear instructions that it is not a security test.
10. **Write `docs/threat-model.md`** describing attacker capabilities, trust boundaries, provider responsibilities, and application responsibilities.
11. **Add a mutation testing script** under `scripts/` using only stdlib code that flips token bits and confirms no mutation returns claims.
12. **Improve error documentation** in `README.md` with a table grouping every `ERROR_CODES` value by parsing, cryptographic, key, header, claim, and configuration failure.
13. **Add packaging regression tests** in `tests/test_package.py` that verify `py.typed` inclusion, project URLs, Python version classifiers, and zero runtime dependencies.
14. **Add explicit typing interoperability tests** in `tests/test_headers.py` for application media type values such as `secevent+jwt` and the rejected `application/` prefix profile choice.
15. **Expand `SECURITY.md`** with a coordinated disclosure timeline, safe report template, and examples of sanitized reproductions.

Before starting one, open an issue or comment on the existing issue so work is not duplicated. Add tests with every code change.
