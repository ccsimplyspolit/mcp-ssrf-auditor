# mcp-ssrf-auditor

[![CI](https://github.com/ccsimplyspolit/mcp-ssrf-auditor/actions/workflows/ci.yml/badge.svg)](https://github.com/ccsimplyspolit/mcp-ssrf-auditor/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-brightgreen.svg)](pyproject.toml)
[![Security: MCP & AI Agents](https://img.shields.io/badge/Security-MCP%20%26%20Agentic%20Auditing-red.svg)](README.md)

Dedicated security evaluation harness and static analyzer for **Model Context Protocol (MCP)** servers, tool specifications, schemas, and runtime configurations.

Designed to detect Server-Side Request Forgery (`CWE-918`), Local File Inclusion / Path Traversal (`CWE-22`), Command Injection (`CWE-78`), and Tool Prompt Poisoning (`CWE-1384`) in AI agent integrations before deployment.

---

## Vulnerability Detection Catalog

| Rule ID | Title | Severity | CWE | Description |
|---|---|---|---|---|
| **MCP-SSRF-001** | Forbidden High-Risk Protocol Scheme | `CRITICAL` | `CWE-918` | Non-HTTP protocol schemes (`file://`, `gopher://`, `dict://`, `tftp://`, etc.) that allow local file disclosure or protocol smuggling. |
| **MCP-SSRF-002** | Trailing Dot Hostname SSRF Bypass | `HIGH` | `CWE-918` | Hostnames with trailing FQDN dots (`localhost.`) that bypass poorly designed regex domain filters while resolving to internal addresses (GHSA-qm7x-j9xp-x3gv pattern). |
| **MCP-SSRF-003** | Localhost / Internal Domain Reference | `CRITICAL` | `CWE-918` | Direct addressing of `localhost`, `*.localhost`, `*.internal`, or loopback aliases. |
| **MCP-SSRF-004** | Cloud Metadata Service Target | `CRITICAL` | `CWE-918` | Cloud instance metadata endpoints (`169.254.169.254`, `metadata.google.internal`) risking cloud token theft. |
| **MCP-SSRF-005** | Obfuscated / Restricted IP Representation | `CRITICAL` | `CWE-918` | Private, loopback, or link-local IPs encoded in decimal (`2130706433`), octal (`0177.0.0.1`), hex (`0x7f000001`), or IPv6 formats. |
| **MCP-PARAM-SSRF-001** | Unrestricted URL Parameter | `HIGH` | `CWE-918` | Schema URL parameters lacking strict enum or regex pattern boundaries. |
| **MCP-PATH-001** | Unbounded File Path Parameter | `HIGH` | `CWE-22` | Path parameters lacking directory sandboxing or canonicalization checks. |
| **MCP-CMD-001** | Arbitrary Command Execution Parameter | `CRITICAL` | `CWE-78` | Raw command strings accepted by tool execution parameters without sub-command enum restrictions. |
| **MCP-POISON-002** | Zero-Width Unicode Steganography | `HIGH` | `CWE-1384` | Concealed zero-width or directional override unicode characters in tool descriptions. |
| **MCP-POISON-003** | Hidden HTML Comment Injection | `HIGH` | `CWE-1384` | HTML comment blocks hiding secondary instructions from human UI rendering. |
| **MCP-POISON-004** | Instruction Override Pattern | `CRITICAL` | `CWE-1384` | Adversarial prompt hijacking directives ("ignore previous instructions") in tool descriptions. |
| **MCP-POISON-005** | Data Exfiltration Directive | `CRITICAL` | `CWE-200` | Tool descriptions instructing LLMs to transmit conversation tokens to external servers. |
| **MCP-CFG-001** | Insecure Runtime Flags | `HIGH` | `CWE-1188` | MCP client configurations launching servers with `--allow-all`, `--no-sandbox`, or relaxed security flags. |
| **MCP-CFG-002** | Hardcoded Secrets in Config | `MEDIUM` | `CWE-798` | API keys or tokens embedded directly in server environment variable maps. |

---

## Installation

```bash
# Clone and install locally
git clone https://github.com/ccsimplyspolit/mcp-ssrf-auditor.git
cd mcp-ssrf-auditor
pip install .
```

Or run directly without installation:

```bash
python -m mcp_ssrf_auditor.cli --help
```

---

## CLI Usage

### 1. Audit MCP Tool Specifications or Manifests

```bash
mcp-ssrf-auditor path/to/mcp_tools.json
```

### 2. Audit Client Configuration Files (Claude Desktop / Cline)

```bash
mcp-ssrf-auditor ~/.config/Claude/claude_desktop_config.json
```

### 3. Direct Target URL Verification

```bash
mcp-ssrf-auditor --verify-url "http://2130706433:8080/admin"
mcp-ssrf-auditor --verify-url "http://169.254.169.254/latest/meta-data/"
mcp-ssrf-auditor --verify-url "http://localhost./api"
```

### 4. Emit SARIF v2.1.0 for GitHub Code Scanning

```bash
mcp-ssrf-auditor tools/ --sarif > results.sarif
```

### 5. Strict CI Enforcement

```bash
# Exit code 1 if ANY warning or finding is present
mcp-ssrf-auditor config.json --strict
```

---

## Python API

```python
from mcp_ssrf_auditor import MCPAuditor, evaluate_target_url

# Direct URL audit
findings = evaluate_target_url("http://0x7f000001:8000/status", target_name="api_tool")
for f in findings:
    print(f"[{f.severity.value}] {f.rule_id}: {f.description}")

# Audit MCP tool schema file
auditor = MCPAuditor()
summary = auditor.audit_schema_file("mcp_tools.json")
print(f"Found {summary.findings_count} security issues across {summary.target_count} tools.")
```

---

## Running Test Suite

```bash
python -m unittest discover -v
```

---

## License

MIT License. See [LICENSE](LICENSE) for details.
