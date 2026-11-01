from pathlib import Path
import unittest

from mcp_ssrf_auditor.analyzer import MCPAuditor, export_sarif

FIXTURES_DIR = Path(__file__).parent / "fixtures"


class TestSchemaAnalyzer(unittest.TestCase):
    def setUp(self):
        self.auditor = MCPAuditor(resolve_dns=False)

    def test_audits_vulnerable_tools_fixture(self):
        fixture_path = FIXTURES_DIR / "vulnerable_tools.json"
        summary = self.auditor.audit_schema_file(fixture_path)

        self.assertEqual(summary.target_count, 3)
        self.assertTrue(summary.has_failures)

        rule_ids = {f.rule_id for f in summary.findings}
        # Check SSRF on URL parameter
        self.assertIn("MCP-PARAM-SSRF-001", rule_ids)
        self.assertIn("MCP-SSRF-004", rule_ids)  # 169.254.169.254 metadata
        # Check LFI on path parameter
        self.assertIn("MCP-PATH-001", rule_ids)
        self.assertIn("MCP-PATH-002", rule_ids)
        # Check Command Injection on cmd parameter
        self.assertIn("MCP-CMD-001", rule_ids)
        # Check poisoning in description
        self.assertIn("MCP-POISON-003", rule_ids)  # HTML comment
        self.assertIn("MCP-POISON-004", rule_ids)  # instruction override

    def test_audits_safe_tools_fixture(self):
        fixture_path = FIXTURES_DIR / "safe_tools.json"
        summary = self.auditor.audit_schema_file(fixture_path)

        self.assertEqual(summary.target_count, 2)
        self.assertEqual(summary.findings_count, 0)
        self.assertFalse(summary.has_failures)

    def test_audits_vulnerable_mcp_config(self):
        fixture_path = FIXTURES_DIR / "vulnerable_mcp_config.json"
        summary = self.auditor.audit_schema_file(fixture_path)

        self.assertEqual(summary.target_count, 1)
        rule_ids = {f.rule_id for f in summary.findings}
        self.assertIn("MCP-CFG-001", rule_ids)  # --allow-all flag
        self.assertIn("MCP-CFG-002", rule_ids)  # OPENAI_API_KEY hardcoded secret
        self.assertIn("MCP-SSRF-005", rule_ids)  # 127.0.0.1 in SSE URL

    def test_exports_valid_sarif_v2_1_0(self):
        fixture_path = FIXTURES_DIR / "vulnerable_tools.json"
        summary = self.auditor.audit_schema_file(fixture_path)
        sarif = export_sarif(summary, tool_version="1.0.0")

        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(sarif["runs"][0]["tool"]["driver"]["name"], "mcp-ssrf-auditor")
        self.assertEqual(sarif["runs"][0]["tool"]["driver"]["version"], "1.0.0")
        self.assertGreater(len(sarif["runs"][0]["results"]), 0)


if __name__ == "__main__":
    unittest.main()
