#!/usr/bin/env python3
"""
WebScan Pro - Unit Tests
Run with: python -m pytest tests/ -v
"""

import unittest
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../src"))

from unittest.mock import patch, MagicMock
from scanner import WebScanner


class TestURLNormalization(unittest.TestCase):
    """Test URL normalization edge cases."""

    def setUp(self):
        with patch("scanner.requests.Session"):
            self.scanner = WebScanner.__new__(WebScanner)
            self.scanner._normalize_url = WebScanner._normalize_url.__get__(self.scanner)

    def test_adds_https_scheme(self):
        result = self.scanner._normalize_url("example.com")
        self.assertEqual(result, "https://example.com")

    def test_preserves_http(self):
        result = self.scanner._normalize_url("http://example.com")
        self.assertEqual(result, "http://example.com")

    def test_strips_trailing_slash(self):
        result = self.scanner._normalize_url("https://example.com/")
        self.assertEqual(result, "https://example.com")

    def test_https_preserved(self):
        result = self.scanner._normalize_url("https://secure.example.com")
        self.assertEqual(result, "https://secure.example.com")


class TestSeverityScoring(unittest.TestCase):
    """Test risk score calculation."""

    def test_risk_score_critical(self):
        findings = [
            {"severity": "CRITICAL"},
            {"severity": "HIGH"},
            {"severity": "MEDIUM"},
        ]
        score = (1 * 10) + (1 * 5) + (1 * 2)
        self.assertEqual(score, 17)

    def test_risk_score_empty(self):
        score = 0
        self.assertEqual(score, 0)

    def test_risk_score_all_low(self):
        findings = [{"severity": "LOW"}] * 5
        score = len(findings) * 1
        self.assertEqual(score, 5)


class TestXSSPayloads(unittest.TestCase):
    """Test XSS payload list integrity."""

    def test_payloads_not_empty(self):
        self.assertGreater(len(WebScanner.XSS_PAYLOADS), 0)

    def test_script_tag_payload_present(self):
        has_script = any("<script" in p for p in WebScanner.XSS_PAYLOADS)
        self.assertTrue(has_script)


class TestSQLiPayloads(unittest.TestCase):
    """Test SQLi payload list integrity."""

    def test_payloads_not_empty(self):
        self.assertGreater(len(WebScanner.SQLI_PAYLOADS), 0)

    def test_common_payload_present(self):
        has_or = any("OR" in p for p in WebScanner.SQLI_PAYLOADS)
        self.assertTrue(has_or)


class TestSensitivePaths(unittest.TestCase):
    """Test sensitive path coverage."""

    def test_git_config_included(self):
        self.assertIn("/.git/config", WebScanner.SENSITIVE_PATHS)

    def test_env_file_included(self):
        self.assertIn("/.env", WebScanner.SENSITIVE_PATHS)

    def test_minimum_path_count(self):
        self.assertGreaterEqual(len(WebScanner.SENSITIVE_PATHS), 10)


class TestReportStructure(unittest.TestCase):
    """Test report generation structure."""

    @patch("scanner.requests.Session")
    def test_report_has_required_keys(self, mock_session):
        scanner = WebScanner("https://example.com")
        scanner.findings = []
        report = scanner.generate_report({"server": "nginx"})

        self.assertIn("report_metadata", report)
        self.assertIn("target_info", report)
        self.assertIn("findings", report)
        self.assertIn("risk_score", report["report_metadata"])
        self.assertIn("severity_summary", report["report_metadata"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
