"""Offline regression tests for the audit's public safety boundaries."""
import importlib.util
import datetime
import json
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
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

    def test_scope_rejects_malformed_numeric_limits_and_ports(self):
        today = datetime.date.today().isoformat()
        base = {"authorization_confirmed": True, "organization": "Example", "authorized_by": "Owner",
                "security_contact": "owner@example.test", "valid_from": today, "expires": today,
                "targets": [{"scheme": "https", "host": "example.test", "port": 443,
                             "allowed_path_prefixes": ["/"]}],
                "max_requests": 5, "max_requests_per_second": 1}
        invalid = [("max_requests", True), ("max_requests", 0.5), ("max_requests", 101),
                   ("max_requests_per_second", True), ("max_requests_per_second", float("nan")),
                   ("max_requests_per_second", float("inf")), ("max_requests_per_second", 0)]
        with tempfile.TemporaryDirectory() as directory:
            scope = Path(directory) / "scope.json"
            scope.write_text(json.dumps(base))
            self.assertEqual(audit.load_scope(scope)[0]["max_requests"], 5)
            for key, value in invalid:
                with self.subTest(key=key, value=value):
                    bad = dict(base, **{key: value})
                    scope.write_text(json.dumps(bad))
                    with self.assertRaises(audit.AuditError):
                        audit.load_scope(scope)
            bad = dict(base, targets=[dict(base["targets"][0], port=True)])
            scope.write_text(json.dumps(bad))
            with self.assertRaises(audit.AuditError):
                audit.load_scope(scope)

            # A malformed live scope must fail during validation, before a request or report.
            scope.write_text(json.dumps(dict(base, max_requests=True)))
            output = Path(directory) / "output"
            result = subprocess.run([sys.executable, str(ROOT / "scripts" / "audit_site.py"),
                                     "https://example.test/", "--scope", str(scope),
                                     "--output-dir", str(output)], capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 2)
            self.assertIn("max_requests", result.stderr)
            self.assertFalse(output.exists())


class HttpSafetyTests(unittest.TestCase):
    def run_fixture(self, status=200, body=b"<html>ok</html>", headers=None, max_requests=1):
        requests = []
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append(self.path)
                self.send_response(status)
                self.send_header("Content-Type", "text/html")
                for key, value in (headers or {}).items():
                    self.send_header(key, value)
                self.end_headers()
                try:
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass
            def log_message(self, *args):
                pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as directory:
                result = subprocess.run([sys.executable, str(ROOT / "scripts" / "audit_site.py"),
                                         f"http://127.0.0.1:{server.server_port}/", "--output-dir", directory,
                                         "--max-requests", str(max_requests), "--rate", "2"],
                                        capture_output=True, text=True, timeout=10)
                report = json.loads((Path(directory) / "findings.json").read_text())
                return result, report, requests
        finally:
            server.shutdown()
            thread.join()
            server.server_close()

    def test_request_ceiling_limits_actual_requests(self):
        result, report, requests = self.run_fixture(max_requests=1)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(len(requests), 1)
        self.assertEqual(report["run"]["requests_made"], 1)

    def test_rate_limit_response_stops_without_retry(self):
        result, report, requests = self.run_fixture(status=429, max_requests=5)
        self.assertEqual(result.returncode, 3)
        self.assertIn("429", report["run"]["stop_reason"])
        self.assertEqual(len(requests), 1)

    def test_login_form_stops_before_following_queued_paths(self):
        result, report, requests = self.run_fixture(body=b'<html><input type="password"></html>', max_requests=5)
        self.assertEqual(result.returncode, 3)
        self.assertIn("login/password", report["run"]["stop_reason"])
        self.assertEqual(len(requests), 1)

    def test_oversized_body_is_discarded(self):
        result, report, requests = self.run_fixture(body=b"x" * (audit.MAX_BODY_BYTES + 1), max_requests=5)
        self.assertEqual(result.returncode, 3)
        self.assertIn("exceeded", report["run"]["stop_reason"])
        self.assertEqual(len(requests), 1)
        self.assertNotIn("x" * 100, json.dumps(report))

    def test_out_of_scope_redirect_is_not_followed(self):
        result, report, requests = self.run_fixture(status=302, headers={"Location": "https://example.test/"}, max_requests=5)
        self.assertEqual(result.returncode, 3)
        self.assertIn("redirect", report["run"]["stop_reason"])
        self.assertEqual(len(requests), 1)


if __name__ == "__main__":
    unittest.main()
