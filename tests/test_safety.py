"""Offline regression tests for the audit's public safety boundaries."""
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("audit_site", ROOT / "scripts" / "audit_site.py")
audit = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = audit
spec.loader.exec_module(audit)


class SafetyTests(unittest.TestCase):
    def setUp(self):
        self.rule = audit.TargetRule("https", "example.test", 443, ("/public/",), ("/public/private",))

    def test_scope_restricts_host_scheme_port_and_exclusions(self):
        self.assertTrue(self.rule.permits("https://example.test/public/page"))
        for url in ("http://example.test/public/page", "https://other.test/public/page",
                    "https://example.test:444/public/page", "https://example.test/public/private/data",
                    "https://user@example.test/public/page"):
            with self.subTest(url=url):
                self.assertFalse(self.rule.permits(url))

    def test_extra_path_outside_scope_is_rejected(self):
        with self.assertRaises(audit.AuditError):
            audit.build_plan("https://example.test/public/", ["/admin"], [self.rule])

    def test_ambiguous_paths_cannot_escape_scope(self):
        for path in ("/public/../admin", "/public/%2e%2e/admin", "/public/%252e%252e/admin", "/public/..\\admin", "/public/%2fadmin"):
            with self.subTest(path=path):
                self.assertFalse(self.rule.permits("https://example.test" + path))
                with self.assertRaises(audit.AuditError):
                    audit.validate_prefixes([path], "allowed")

    def test_redirect_handler_never_follows_redirects(self):
        self.assertIsNone(audit.NoRedirect().redirect_request(None, None, 302, "Found", {}, "https://other.test/"))

    def test_secret_is_not_written_to_finding(self):
        secret = "ghp_" + "A" * 40
        findings = audit.secret_candidates(secret, "fixture.js")
        self.assertTrue(findings)
        self.assertNotIn(secret, json.dumps(findings))
        self.assertEqual(len(findings[0]["evidence"]["sha256_12"]), 12)

    def test_password_and_sensitive_fields_raise_stop_signals(self):
        parser = audit.PublicPageParser()
        parser.feed('<form><input type="password"></form>')
        self.assertTrue(parser.password_input)
        self.assertIsNotNone(audit.sensitive_data_indicator('{"ssn":"fixture"}'))

    def test_non_loopback_requires_scope_even_for_dry_run(self):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run([sys.executable, str(ROOT / "scripts" / "audit_site.py"),
                                     "https://example.test/", "--dry-run", "--output-dir", directory],
                                    capture_output=True, text=True, timeout=5)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("require --scope", result.stderr)


if __name__ == "__main__":
    unittest.main()
