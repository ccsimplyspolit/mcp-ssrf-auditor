from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from .models import Finding, ResourceDefinition, ScanSummary, Severity, ToolDefinition
from .poisoning_detector import audit_tool_metadata
from .ssrf_validator import evaluate_target_url

PATH_PARAM_NAMES = {"path", "filepath", "filename", "file", "directory", "dir", "folder", "dest", "destination", "source"}
URL_PARAM_NAMES = {"url", "uri", "endpoint", "webhook", "webhook_url", "target_url", "callback", "destination_url"}
CMD_PARAM_NAMES = {"cmd", "command", "exec", "script", "shell_cmd", "bash", "execute"}
SECRET_KEYWORDS = {"api_key", "apikey", "secret", "token", "password", "auth", "private_key", "bearer"}

SECRET_VALUE_RE = re.compile(
    r"(?:sk-(?:proj-)?[a-zA-Z0-9_-]{20,}|ghp_[a-zA-Z0-9]{30,}|gho_[a-zA-Z0-9]{30,}|AKIA[0-9A-Z]{16}|ey[a-zA-Z0-9_-]{20,}\.ey[a-zA-Z0-9_-]{20,})"
)


class MCPAuditor:
    """Core auditing engine for Model Context Protocol servers, schemas, and configurations."""

    def __init__(self, resolve_dns: bool = False, max_description_len: int = 1500):
        self.resolve_dns = resolve_dns
        self.max_description_len = max_description_len

    def audit_tool(self, tool: ToolDefinition) -> List[Finding]:
        """Audit an individual MCP tool definition."""
        findings: List[Finding] = []

        # 1. Audit descriptions for poisoning / prompt injection
        findings.extend(audit_tool_metadata(tool, max_description_length=self.max_description_len))

        # 2. Inspect input schema properties
        properties = tool.input_schema.get("properties", {})
        required = set(tool.input_schema.get("required", []))

        if isinstance(properties, dict):
            for param_name, param_spec in properties.items():
                if not isinstance(param_spec, dict):
                    continue

                param_type = param_spec.get("type", "string")
                param_lower = param_name.lower()
                param_desc = param_spec.get("description", "")
                param_default = param_spec.get("default")
                param_enum = param_spec.get("enum")
                param_pattern = param_spec.get("pattern")

                # SSRF audit on URL parameters
                if param_lower in URL_PARAM_NAMES or "url" in param_lower:
                    if not param_pattern and not param_enum:
                        findings.append(
                            Finding(
                                rule_id="MCP-PARAM-SSRF-001",
                                title=f"Unrestricted URL Parameter '{param_name}'",
                                severity=Severity.HIGH,
                                cwe="CWE-918",
                                target=tool.name,
                                parameter=param_name,
                                description=(
                                    f"Tool '{tool.name}' accepts URL parameter '{param_name}' without schema-level "
                                    f"pattern restrictions or domain enum constraints, exposing server to SSRF."
                                ),
                                remediation=(
                                    "Define explicit `pattern` or `enum` restricting destinations, and validate "
                                    "resolved IP addresses against RFC 1918 / loopback ranges at runtime."
                                ),
                                line=tool.line,
                                file_path=tool.file_path,
                            )
                        )

                    # Check default value for SSRF
                    if isinstance(param_default, str) and param_default:
                        ssrf_findings = evaluate_target_url(
                            param_default,
                            target_name=tool.name,
                            parameter_name=param_name,
                            resolve_dns=self.resolve_dns,
                            file_path=tool.file_path,
                            line=tool.line,
                        )
                        findings.extend(ssrf_findings)

                # Path Traversal audit on Path parameters
                if param_lower in PATH_PARAM_NAMES or "path" in param_lower:
                    if not param_pattern and not param_enum:
                        findings.append(
                            Finding(
                                rule_id="MCP-PATH-001",
                                title=f"Unbounded File Path Parameter '{param_name}' (LFI/Traversal)",
                                severity=Severity.HIGH,
                                cwe="CWE-22",
                                target=tool.name,
                                parameter=param_name,
                                description=(
                                    f"Tool '{tool.name}' accepts path parameter '{param_name}' without path traversal "
                                    f"guards or safe directory boundaries, risking arbitrary file read/write."
                                ),
                                remediation=(
                                    "Enforce workspace confinement via `os.path.realpath` / canonical path validation "
                                    "and verify that resolved targets lie strictly inside designated directories."
                                ),
                                line=tool.line,
                                file_path=tool.file_path,
                            )
                        )

                    # Check default path value
                    if isinstance(param_default, str) and (".." in param_default or param_default.startswith("/")):
                        findings.append(
                            Finding(
                                rule_id="MCP-PATH-002",
                                title=f"Suspicious Default Path in Parameter '{param_name}'",
                                severity=Severity.HIGH,
                                cwe="CWE-22",
                                target=tool.name,
                                parameter=param_name,
                                description=(
                                    f"Tool '{tool.name}' parameter '{param_name}' specifies default path "
                                    f"'{param_default}' referencing parent directory or root traversal."
                                ),
                                remediation="Provide benign relative default paths within safe sandboxes.",
                                line=tool.line,
                                file_path=tool.file_path,
                            )
                        )

                # Command Injection audit on Exec parameters
                if param_lower in CMD_PARAM_NAMES:
                    if not param_enum:
                        findings.append(
                            Finding(
                                rule_id="MCP-CMD-001",
                                title=f"Arbitrary Command Execution Parameter '{param_name}'",
                                severity=Severity.CRITICAL,
                                cwe="CWE-78",
                                target=tool.name,
                                parameter=param_name,
                                description=(
                                    f"Tool '{tool.name}' parameter '{param_name}' accepts arbitrary shell command strings. "
                                    f"If invoked by an agent without strict argument arrays, this allows Remote Code Execution."
                                ),
                                remediation=(
                                    "Disallow raw command string arguments. Use fixed enum subcommands and execute via "
                                    "direct process spawning without shell (`shell=False`, argument list)."
                                ),
                                line=tool.line,
                                file_path=tool.file_path,
                            )
                        )

                # Secret leakage in schema parameter definitions
                if isinstance(param_default, str) and SECRET_VALUE_RE.search(param_default):
                    findings.append(
                        Finding(
                            rule_id="MCP-SECRET-001",
                            title=f"Hardcoded API Token / Secret in Parameter '{param_name}' Default",
                            severity=Severity.HIGH,
                            cwe="CWE-532",
                            target=tool.name,
                            parameter=param_name,
                            description=(
                                f"Parameter '{param_name}' in tool '{tool.name}' exposes live secret or API token "
                                f"in default value."
                            ),
                            remediation="Inject authentication tokens through secure server-side environment variables.",
                            line=tool.line,
                            file_path=tool.file_path,
                        )
                    )

        return findings

    def audit_resource(self, res: ResourceDefinition) -> List[Finding]:
        """Audit an MCP resource definition."""
        findings: List[Finding] = []
        uri = res.uri.strip()

        if uri.startswith("file://"):
            # Check for directory traversal or sensitive paths in resource URI
            if ".." in uri or "/etc/" in uri or "/proc/" in uri or "C:\\Windows" in uri:
                findings.append(
                    Finding(
                        rule_id="MCP-RES-001",
                        title=f"Sensitive or Traversal Path in Resource URI '{res.name or uri}'",
                        severity=Severity.HIGH,
                        cwe="CWE-22",
                        target=res.name or uri,
                        parameter="uri",
                        description=f"Resource exposes file URI '{uri}' targeting sensitive system path.",
                        remediation="Confine file resource URIs to authorized sandbox directories.",
                        line=res.line,
                        file_path=res.file_path,
                    )
                )
        elif uri.startswith("http://") or uri.startswith("https://"):
            ssrf_findings = evaluate_target_url(
                uri,
                target_name=res.name or uri,
                parameter_name="uri",
                resolve_dns=self.resolve_dns,
                file_path=res.file_path,
                line=res.line,
            )
            findings.extend(ssrf_findings)

        return findings

    def audit_server_config(self, config_dict: Dict[str, Any], file_path: str = "<config>") -> List[Finding]:
        """Audit an MCP server config file (e.g. claude_desktop_config.json, mcp.json)."""
        findings: List[Finding] = []
        servers = config_dict.get("mcpServers", {})

        if not isinstance(servers, dict):
            return findings

        for server_name, server_spec in servers.items():
            if not isinstance(server_spec, dict):
                continue

            command = server_spec.get("command", "")
            args = server_spec.get("args", [])
            env = server_spec.get("env", {})
            url = server_spec.get("url", "")

            # Check SSE transport URL
            if url:
                ssrf_res = evaluate_target_url(
                    url,
                    target_name=f"server:{server_name}",
                    parameter_name="url",
                    resolve_dns=self.resolve_dns,
                    file_path=file_path,
                )
                findings.extend(ssrf_res)

            # Check dangerous command-line flags
            arg_str = " ".join(args)
            if "--allow-all" in arg_str or "--no-sandbox" in arg_str or "--dangerously-skip-permissions" in arg_str:
                findings.append(
                    Finding(
                        rule_id="MCP-CFG-001",
                        title=f"Insecure Runtime Flags in Server '{server_name}'",
                        severity=Severity.HIGH,
                        cwe="CWE-1188",
                        target=server_name,
                        parameter="args",
                        description=(
                            f"Server '{server_name}' runs with permissive flags ('{arg_str}'), "
                            f"disabling security sandboxing or permission barriers."
                        ),
                        remediation="Remove insecure flags and adhere to principle of least privilege.",
                        file_path=file_path,
                    )
                )

            # Check hardcoded secrets in env
            if isinstance(env, dict):
                for env_k, env_v in env.items():
                    is_secret_key = any(kw in env_k.lower() for kw in SECRET_KEYWORDS)
                    if isinstance(env_v, str) and (SECRET_VALUE_RE.search(env_v) or (is_secret_key and len(env_v) > 5)):
                        findings.append(
                            Finding(
                                rule_id="MCP-CFG-002",
                                title=f"Hardcoded Secret in Environment Variable '{env_k}'",
                                severity=Severity.MEDIUM,
                                cwe="CWE-798",
                                target=server_name,
                                parameter=env_k,
                                description=(
                                    f"Server '{server_name}' embeds credential string in config variable '{env_k}'."
                                ),
                                remediation="Load credentials from system environment variables or secrets manager.",
                                file_path=file_path,
                            )
                        )

        return findings

    def audit_schema_file(self, path: Union[str, Path]) -> ScanSummary:
        """Parse and audit a JSON file containing tool definitions, resources, or an MCP config."""
        path = Path(path)
        content = path.read_text(encoding="utf-8")
        data = json.loads(content)

        findings: List[Finding] = []
        target_count = 0

        # Case 1: Config with mcpServers
        if "mcpServers" in data:
            cfg_findings = self.audit_server_config(data, file_path=str(path))
            findings.extend(cfg_findings)
            target_count += len(data.get("mcpServers", {}))

        # Case 2: List of tools in standard tools/list format
        tools = data.get("tools", [])
        if isinstance(tools, list):
            for item in tools:
                if isinstance(item, dict) and "name" in item:
                    target_count += 1
                    t = ToolDefinition(
                        name=item.get("name", "unnamed"),
                        description=item.get("description", ""),
                        input_schema=item.get("inputSchema", {}),
                        file_path=str(path),
                    )
                    findings.extend(self.audit_tool(t))

        # Case 3: List of resources
        resources = data.get("resources", [])
        if isinstance(resources, list):
            for res in resources:
                if isinstance(res, dict) and "uri" in res:
                    target_count += 1
                    r = ResourceDefinition(
                        uri=res["uri"],
                        name=res.get("name"),
                        mime_type=res.get("mimeType"),
                        description=res.get("description"),
                        file_path=str(path),
                    )
                    findings.extend(self.audit_resource(r))

        # Case 4: Single tool object
        if "name" in data and "inputSchema" in data:
            target_count += 1
            t = ToolDefinition(
                name=data["name"],
                description=data.get("description", ""),
                input_schema=data["inputSchema"],
                file_path=str(path),
            )
            findings.extend(self.audit_tool(t))

        critical_c = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        high_c = sum(1 for f in findings if f.severity == Severity.HIGH)
        medium_c = sum(1 for f in findings if f.severity == Severity.MEDIUM)
        low_c = sum(1 for f in findings if f.severity == Severity.LOW)
        info_c = sum(1 for f in findings if f.severity == Severity.INFO)

        return ScanSummary(
            target_count=target_count,
            findings_count=len(findings),
            critical_count=critical_c,
            high_count=high_c,
            medium_count=medium_c,
            low_count=low_c,
            info_count=info_c,
            findings=findings,
        )


def export_sarif(summary: ScanSummary, tool_version: str = "1.0.0") -> Dict[str, Any]:
    """Export audit findings as OASIS SARIF v2.1.0 JSON object for GitHub Code Scanning."""
    rules_map: Dict[str, Dict[str, Any]] = {}
    results = []

    for f in summary.findings:
        level_map = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.INFO: "note",
        }

        if f.rule_id not in rules_map:
            rules_map[f.rule_id] = {
                "id": f.rule_id,
                "name": f.title,
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.description},
                "help": {"text": f"Remediation: {f.remediation}"},
                "properties": {
                    "tags": ["security", "mcp", "ssrf"],
                    "precision": "high",
                    "cwe": [f.cwe],
                },
            }

        res_entry: Dict[str, Any] = {
            "ruleId": f.rule_id,
            "level": level_map.get(f.severity, "warning"),
            "message": {"text": f"{f.title}: {f.description} (Remediation: {f.remediation})"},
        }

        if f.file_path:
            res_entry["locations"] = [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.file_path},
                        "region": {"startLine": f.line or 1},
                    }
                }
            ]

        results.append(res_entry)

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "mcp-ssrf-auditor",
                        "version": tool_version,
                        "informationUri": "https://github.com/ccsimplyspolit/mcp-ssrf-auditor",
                        "rules": list(rules_map.values()),
                    }
                },
                "results": results,
            }
        ],
    }
