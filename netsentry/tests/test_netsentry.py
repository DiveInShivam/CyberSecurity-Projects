#!/usr/bin/env python3
"""
NetSentry - Unit Tests
Run with: python -m pytest tests/ -v
"""

import unittest
import sys
import os
import json
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../src"))
from netsentry import PortScanner, AnomalyDetector, SecureLogManager, build_report, PORT_DB, RISK_WEIGHTS


class TestPortDatabase(unittest.TestCase):
    """Validate port intelligence database entries."""

    def test_critical_ports_present(self):
        critical = [p for p, v in PORT_DB.items() if v["risk"] == "CRITICAL"]
        self.assertGreater(len(critical), 3)

    def test_telnet_is_critical(self):
        self.assertEqual(PORT_DB[23]["risk"], "CRITICAL")

    def test_ssh_is_low_risk(self):
        self.assertEqual(PORT_DB[22]["risk"], "LOW")

    def test_all_entries_have_required_keys(self):
        for port, info in PORT_DB.items():
            self.assertIn("service", info, f"Port {port} missing 'service'")
            self.assertIn("risk", info, f"Port {port} missing 'risk'")
            self.assertIn("note", info, f"Port {port} missing 'note'")

    def test_risk_values_valid(self):
        valid_risks = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}
        for port, info in PORT_DB.items():
            self.assertIn(info["risk"], valid_risks, f"Port {port} has invalid risk")


class TestPortScanner(unittest.TestCase):
    """Test port range parsing logic."""

    def setUp(self):
        # Bypass actual DNS for unit tests
        self.scanner = PortScanner.__new__(PortScanner)
        self.scanner._parse_port_range = PortScanner._parse_port_range.__get__(self.scanner)

    def test_single_port(self):
        result = self.scanner._parse_port_range("80")
        self.assertEqual(result, [80])

    def test_port_range(self):
        result = self.scanner._parse_port_range("80-83")
        self.assertEqual(result, [80, 81, 82, 83])

    def test_csv_ports(self):
        result = self.scanner._parse_port_range("22,80,443")
        self.assertEqual(result, [22, 80, 443])

    def test_top100_returns_list(self):
        result = self.scanner._parse_port_range("top100")
        self.assertIsInstance(result, list)
        self.assertGreater(len(result), 50)
        self.assertIn(80, result)
        self.assertIn(443, result)

    def test_no_duplicate_ports_in_top100(self):
        result = self.scanner._parse_port_range("top100")
        self.assertEqual(len(result), len(set(result)))


class TestAnomalyDetector(unittest.TestCase):
    """Test anomaly detection rule matching."""

    def setUp(self):
        self.detector = AnomalyDetector()

    def _make_ports(self, port_list):
        return [{"port": p, "state": "open", "service": "test", "risk": "LOW", "note": ""} for p in port_list]

    def test_telnet_triggers_rule(self):
        ports = self._make_ports([23])
        anomalies = self.detector.analyze(ports)
        names = [a["name"] for a in anomalies]
        self.assertIn("Telnet Exposed", names)

    def test_rdp_triggers_critical(self):
        ports = self._make_ports([3389])
        anomalies = self.detector.analyze(ports)
        rdp = next((a for a in anomalies if a["name"] == "RDP Exposed"), None)
        self.assertIsNotNone(rdp)
        self.assertEqual(rdp["severity"], "CRITICAL")

    def test_no_open_ports_no_anomalies(self):
        anomalies = self.detector.analyze([])
        self.assertEqual(anomalies, [])

    def test_safe_ports_no_anomalies(self):
        ports = self._make_ports([22, 443])
        anomalies = self.detector.analyze(ports)
        self.assertEqual(len(anomalies), 0)

    def test_multiple_db_ports_trigger_one_rule(self):
        ports = self._make_ports([3306, 5432])  # Both match RULE-002
        anomalies = self.detector.analyze(ports)
        rule_002 = [a for a in anomalies if a.get("rule_id") == "RULE-002"]
        self.assertEqual(len(rule_002), 1)
        self.assertEqual(len(rule_002[0]["matched_ports"]), 2)

    def test_anomalies_sorted_by_severity(self):
        ports = self._make_ports([23, 21, 80])  # CRITICAL, HIGH, MEDIUM
        anomalies = self.detector.analyze(ports)
        if len(anomalies) > 1:
            scores = [RISK_WEIGHTS.get(a["severity"], 0) for a in anomalies]
            self.assertEqual(scores, sorted(scores, reverse=True))


class TestRiskScoring(unittest.TestCase):
    """Test risk score calculation."""

    def test_risk_weights_defined(self):
        self.assertIn("CRITICAL", RISK_WEIGHTS)
        self.assertIn("HIGH", RISK_WEIGHTS)
        self.assertGreater(RISK_WEIGHTS["CRITICAL"], RISK_WEIGHTS["HIGH"])

    def test_report_risk_score(self):
        open_ports = [
            {"port": 23, "state": "open", "service": "Telnet", "risk": "CRITICAL", "note": ""},
        ]
        anomalies = []
        report = build_report("test.com", "1.2.3.4", open_ports, anomalies)
        self.assertEqual(report["report_metadata"]["risk_score"], RISK_WEIGHTS["CRITICAL"])


class TestSecureLogManager(unittest.TestCase):
    """Test HMAC-signed log integrity."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.log_mgr = SecureLogManager(log_dir=self.tmpdir, secret="test-secret")

    def test_write_creates_file(self):
        report = {"test": "data", "risk_score": 5}
        filepath = self.log_mgr.write(report)
        self.assertTrue(os.path.exists(filepath))

    def test_verify_valid_log(self):
        report = {"data": "value", "numbers": [1, 2, 3]}
        filepath = self.log_mgr.write(report)
        self.assertTrue(self.log_mgr.verify(filepath))

    def test_detect_tampered_log(self):
        report = {"data": "original"}
        filepath = self.log_mgr.write(report)

        # Tamper with the file
        with open(filepath) as f:
            content = json.load(f)
        content["data"] = "tampered"
        with open(filepath, "w") as f:
            json.dump(content, f)

        self.assertFalse(self.log_mgr.verify(filepath))

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)


class TestReportBuilder(unittest.TestCase):
    """Test report structure."""

    def test_report_has_all_sections(self):
        report = build_report("example.com", "1.1.1.1", [], [], [])
        self.assertIn("report_metadata", report)
        self.assertIn("open_ports", report)
        self.assertIn("anomalies", report)
        self.assertIn("recommendations", report)

    def test_recommendations_not_empty(self):
        report = build_report("example.com", "1.1.1.1", [], [], [])
        self.assertGreater(len(report["recommendations"]), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
