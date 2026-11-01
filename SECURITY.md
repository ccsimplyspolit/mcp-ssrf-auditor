# Security Policy & Coordinated Vulnerability Disclosure (CVD)

## Scope & Defensive Purpose

`mcp-ssrf-auditor` is a defensive security evaluation harness and static analyzer for Model Context Protocol (MCP) servers, tool schemas, and runtime configurations covering SSRF (`CWE-918`), path traversal (`CWE-22`), command injection (`CWE-78`), and tool prompt poisoning (`CWE-1384`).

All tooling in this repository is published strictly for defensive auditing, continuous integration hardening, and Coordinated Vulnerability Disclosure (CVD).

## Supported Versions

| Version | Supported |
| --- | :---: |
| `1.0.x` | :white_check_mark: |
| `< 1.0.0` | :x: |

## Reporting a Vulnerability

Please **do not** report security vulnerabilities in `mcp-ssrf-auditor` (such as parser bypasses, SARIF injection issues, or pathological regex/AST denial-of-service inputs) through public GitHub issues.

Use one of the following private reporting channels:

1. **GitHub Private Vulnerability Reporting (Preferred):**  
   Submit a confidential advisory directly via [`https://github.com/ccsimplyspolit/mcp-ssrf-auditor/security/advisories/new`](https://github.com/ccsimplyspolit/mcp-ssrf-auditor/security/advisories/new).
2. **Direct Researcher Contact:**  
   Email **`cc.simply.spolit@gmail.com`** with `[SECURITY] mcp-ssrf-auditor` in the subject line.
   - **Maintainer:** Serhii Shunko (`@ccsimplyspolit`)
   - **ORCID:** [`0009-0002-4183-0361`](https://orcid.org/0009-0002-4183-0361)
   - **Research Portal:** [`https://ccsimplyspolit.github.io`](https://ccsimplyspolit.github.io)

## Disclosure & Remediation Timeline

We follow a standard **90-day Coordinated Vulnerability Disclosure (CVD)** workflow:

- **Acknowledgment:** Within **48 hours** of report receipt.
- **Triage & Reproduction:** Within **5 business days**, including severity classification (CVSS v3.1 / v4.0) and CWE mapping.
- **Remediation & Advisory:** Patches are released alongside a published GitHub Security Advisory (GHSA) crediting the reporting researcher unless anonymity is requested.
