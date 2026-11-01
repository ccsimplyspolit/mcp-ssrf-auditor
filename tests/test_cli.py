from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import unittest

from mcp_ssrf_auditor.cli import main

FIXTURES_DIR = Path(__file__).parent / "fixtures"


class TestCLI(unittest.TestCase):
    def test_cli_audits_safe_fixture_returns_zero(self):
        safe_fixture = str(FIXTURES_DIR / "safe_tools.json")
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main([safe_fixture])
        self.assertEqual(rc, 0)
        self.assertIn("Found 0 finding(s)", buf.getvalue())

    def test_cli_audits_vulnerable_fixture_returns_one(self):
        vuln_fixture = str(FIXTURES_DIR / "vulnerable_tools.json")
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main([vuln_fixture])
        self.assertEqual(rc, 1)
        self.assertIn("CRITICAL", buf.getvalue())

    def test_cli_verify_url_flag(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["--verify-url", "http://169.254.169.254/latest/"])
        self.assertEqual(rc, 1)
        self.assertIn("MCP-SSRF-004", buf.getvalue())

    def test_cli_json_output(self):
        vuln_fixture = str(FIXTURES_DIR / "vulnerable_tools.json")
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main([vuln_fixture, "--json"])
        self.assertEqual(rc, 1)
        data = json.loads(buf.getvalue())
        self.assertIn("summary", data)
        self.assertIn("findings", data)
        self.assertGreater(data["summary"]["total_findings"], 0)

    def test_cli_sarif_output(self):
        vuln_fixture = str(FIXTURES_DIR / "vulnerable_tools.json")
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main([vuln_fixture, "--sarif"])
        self.assertEqual(rc, 1)
        sarif = json.loads(buf.getvalue())
        self.assertEqual(sarif["version"], "2.1.0")


if __name__ == "__main__":
    unittest.main()
