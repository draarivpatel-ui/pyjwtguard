"""Package metadata, public API, and repository hygiene tests."""

import ast
import re
import unittest
from pathlib import Path

import pyjwtguard
from pyjwtguard import ERROR_CODES

ROOT = Path(__file__).resolve().parents[1]


def read(relative):
    return (ROOT / relative).read_text(encoding="utf-8")


def project_files():
    skipped = {".git", "__pycache__", ".pytest_cache", "build", "dist"}
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        if any(part in skipped for part in path.parts):
            continue
        if path.suffix in {".pyc", ".pyo"}:
            continue
        yield path


class PackageMetadataTests(unittest.TestCase):
    def test_runtime_dependencies_are_empty(self):
        self.assertIn("dependencies = []", read("pyproject.toml"))

    def test_python_floor_is_39(self):
        self.assertIn('requires-python = ">=3.9"', read("pyproject.toml"))

    def test_project_urls_point_to_public_repository(self):
        text = read("pyproject.toml")
        self.assertIn('Homepage = "https://github.com/draarivpatel-ui/pyjwtguard"', text)
        self.assertIn('Repository = "https://github.com/draarivpatel-ui/pyjwtguard"', text)
        self.assertIn('Issues = "https://github.com/draarivpatel-ui/pyjwtguard/issues"', text)

    def test_version_matches_package(self):
        self.assertIn('version = "1.0.0"', read("pyproject.toml"))
        self.assertEqual("1.0.0", pyjwtguard.__version__)

    def test_py_typed_is_present(self):
        self.assertTrue((ROOT / "src" / "pyjwtguard" / "py.typed").is_file())

    def test_src_layout_is_used(self):
        self.assertIn('package-dir = { "" = "src" }', read("pyproject.toml"))
        self.assertTrue((ROOT / "src" / "pyjwtguard" / "__init__.py").is_file())


class WorkflowTests(unittest.TestCase):
    def test_ci_uses_ubuntu_2404(self):
        self.assertIn("runs-on: ubuntu-24.04", read(".github/workflows/ci.yml"))

    def test_ci_matrix_covers_python_39_to_313(self):
        text = read(".github/workflows/ci.yml")
        for version in ("3.9", "3.10", "3.11", "3.12", "3.13"):
            self.assertIn('"' + version + '"', text)

    def test_ci_runs_unittest_suite(self):
        self.assertIn("PYTHONPATH=src python3 -m unittest discover -s tests", read(".github/workflows/ci.yml"))

    def test_publish_uses_oidc_trusted_publishing_permission(self):
        text = read(".github/workflows/publish.yml")
        self.assertIn("id-token: write", text)
        self.assertIn("pypa/gh-action-pypi-publish@release/v1", text)

    def test_publish_workflow_targets_pypi_environment(self):
        text = read(".github/workflows/publish.yml")
        self.assertIn("name: pypi", text)
        self.assertIn("url: https://pypi.org/p/pyjwtguard", text)


class DocumentationTests(unittest.TestCase):
    def test_required_documents_exist(self):
        for relative in ("README.md", "SECURITY.md", "CONTRIBUTING.md", "LICENSE", "docs/good-first-issues.md"):
            self.assertTrue((ROOT / relative).is_file(), relative)

    def test_good_first_issues_has_fifteen_items(self):
        count = len(re.findall(r"^\d+\. \*\*", read("docs/good-first-issues.md"), re.MULTILINE))
        self.assertEqual(15, count)

    def test_readme_documents_hmac_only_stdlib_scope(self):
        text = read("README.md")
        self.assertIn("constant-time HMAC", text)
        self.assertIn("RSA, ECDSA, EdDSA", text)
        self.assertIn("provider protocol", text)

    def test_readme_warns_that_unverified_output_is_attacker_controlled(self):
        self.assertIn("attacker controlled", read("README.md"))

    def test_security_policy_has_private_reporting_path(self):
        self.assertIn("private security advisory", read("SECURITY.md"))


class PublicApiTests(unittest.TestCase):
    def test_decode_unverified_is_exported(self):
        self.assertIn("decode_unverified", pyjwtguard.__all__)

    def test_decode_unsafe_is_not_exported(self):
        self.assertNotIn("decode_unsafe", pyjwtguard.__all__)
        self.assertFalse(hasattr(pyjwtguard, "decode_unsafe"))

    def test_error_codes_are_unique(self):
        self.assertEqual(len(ERROR_CODES), len(set(ERROR_CODES)))

    def test_error_codes_are_uppercase_machine_readable(self):
        for code in ERROR_CODES:
            self.assertRegex(code, r"^[A-Z0-9_]+$")

    def test_required_public_names_exist(self):
        for name in (
            "AlgorithmProvider",
            "HmacKey",
            "JwtGuardError",
            "decode_unverified",
            "inspect_header",
            "inspect_token",
            "sign_jwt",
            "verify_jwt",
        ):
            self.assertTrue(hasattr(pyjwtguard, name), name)


class SourceHygieneTests(unittest.TestCase):
    def test_source_has_no_third_party_imports(self):
        allowed = {
            "__future__",
            "argparse",
            "base64",
            "binascii",
            "collections",
            "dataclasses",
            "hashlib",
            "hmac",
            "json",
            "math",
            "re",
            "secrets",
            "sys",
            "time",
            "types",
            "typing",
            "unicodedata",
            "pyjwtguard",
        }
        for path in (ROOT / "src" / "pyjwtguard").glob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    names = [alias.name.split(".")[0] for alias in node.names]
                elif isinstance(node, ast.ImportFrom):
                    if node.level:
                        continue
                    names = [(node.module or "").split(".")[0]]
                else:
                    continue
                for name in names:
                    self.assertIn(name, allowed, "{} imports {}".format(path.name, name))

    def test_tracked_text_has_no_em_or_en_dashes(self):
        forbidden = (chr(0x2013), chr(0x2014))
        for path in project_files():
            text = path.read_text(encoding="utf-8", errors="ignore")
            for char in forbidden:
                self.assertNotIn(char, text, "{} contains a Unicode dash".format(path))

    def test_tracked_text_has_no_local_private_markers(self):
        markers = (
            "/" + "Users/",
            "someone@" + "gmail.com",
            "handle-redacted286@" + "gmail.com",
            "Exampleton" + " Manor",
        )
        for path in project_files():
            text = path.read_text(encoding="utf-8", errors="ignore")
            for marker in markers:
                self.assertNotIn(marker, text, "{} contains a private marker".format(path))

    def test_source_does_not_export_decode_unsafe_alias(self):
        for path in (ROOT / "src" / "pyjwtguard").glob("*.py"):
            self.assertNotIn("decode_unsafe", path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
