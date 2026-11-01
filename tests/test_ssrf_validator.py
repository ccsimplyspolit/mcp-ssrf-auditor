import unittest

from mcp_ssrf_auditor.models import Severity
from mcp_ssrf_auditor.ssrf_validator import (
    evaluate_target_url,
    is_private_or_restricted_ip,
    parse_ip_ambiguous,
)


class TestSSRFValidator(unittest.TestCase):
    def test_parse_ambiguous_ip_encodings(self):
        # Standard decimal dotted
        ip = parse_ip_ambiguous("127.0.0.1")
        self.assertIsNotNone(ip)
        self.assertEqual(str(ip), "127.0.0.1")

        # Decimal integer format (2130706433 == 127.0.0.1)
        ip_dec = parse_ip_ambiguous("2130706433")
        self.assertIsNotNone(ip_dec)
        self.assertEqual(str(ip_dec), "127.0.0.1")

        # Hex format (0x7f000001 == 127.0.0.1)
        ip_hex = parse_ip_ambiguous("0x7f000001")
        self.assertIsNotNone(ip_hex)
        self.assertEqual(str(ip_hex), "127.0.0.1")

        # Octal format (0177.0.0.1 == 127.0.0.1)
        ip_oct = parse_ip_ambiguous("0177.0.0.1")
        self.assertIsNotNone(ip_oct)
        self.assertEqual(str(ip_oct), "127.0.0.1")

    def test_detects_forbidden_schemes(self):
        findings = evaluate_target_url("file:///etc/shadow", target_name="test_tool")
        rule_ids = {f.rule_id for f in findings}
        self.assertIn("MCP-SSRF-001", rule_ids)
        self.assertTrue(any(f.severity == Severity.CRITICAL for f in findings))

        findings_gopher = evaluate_target_url("gopher://127.0.0.1:6379/_flushall", target_name="test_tool")
        self.assertTrue(any(f.rule_id == "MCP-SSRF-001" for f in findings_gopher))

    def test_detects_cloud_metadata_service(self):
        findings = evaluate_target_url("http://169.254.169.254/latest/meta-data/", target_name="test_tool")
        rule_ids = {f.rule_id for f in findings}
        self.assertIn("MCP-SSRF-004", rule_ids)
        self.assertIn("MCP-SSRF-005", rule_ids)

        findings_gcp = evaluate_target_url("http://metadata.google.internal/computeMetadata/v1/", target_name="test_tool")
        self.assertTrue(any(f.rule_id == "MCP-SSRF-004" for f in findings_gcp))

    def test_detects_trailing_dot_ssrf_bypass(self):
        # Trailing dot hostname bypass (GHSA-qm7x-j9xp-x3gv pattern)
        findings = evaluate_target_url("http://localhost./api/v1", target_name="test_tool")
        rule_ids = {f.rule_id for f in findings}
        self.assertIn("MCP-SSRF-002", rule_ids)
        self.assertIn("MCP-SSRF-003", rule_ids)

    def test_detects_obfuscated_private_ips(self):
        # Hex 0x7f000001 (127.0.0.1)
        findings = evaluate_target_url("http://0x7f000001/admin", target_name="test_tool")
        self.assertTrue(any(f.rule_id == "MCP-SSRF-005" for f in findings))

        # Octal 0177.0.0.1 (127.0.0.1)
        findings_oct = evaluate_target_url("http://0177.0.0.1/admin", target_name="test_tool")
        self.assertTrue(any(f.rule_id == "MCP-SSRF-005" for f in findings_oct))

        # Decimal 2130706433
        findings_dec = evaluate_target_url("http://2130706433:8080/", target_name="test_tool")
        self.assertTrue(any(f.rule_id == "MCP-SSRF-005" for f in findings_dec))

    def test_allows_valid_public_https_url(self):
        findings = evaluate_target_url("https://api.github.com/repos/octocat/hello-world", target_name="test_tool")
        self.assertEqual(len(findings), 0)


if __name__ == "__main__":
    unittest.main()
