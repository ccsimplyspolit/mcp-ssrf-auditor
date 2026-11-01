"""
mcp-ssrf-auditor
Security evaluation harness and static analyzer for Model Context Protocol (MCP) servers.
Detects SSRF, Path Traversal (LFI), Command Execution, and Tool Metadata Prompt Poisoning.
"""

from .analyzer import MCPAuditor, export_sarif
from .models import Finding, ResourceDefinition, ScanSummary, Severity, ToolDefinition
from .poisoning_detector import audit_tool_metadata
from .ssrf_validator import evaluate_target_url, is_private_or_restricted_ip, parse_ip_ambiguous

__version__ = "1.0.0"

__all__ = [
    "MCPAuditor",
    "Finding",
    "Severity",
    "ToolDefinition",
    "ResourceDefinition",
    "ScanSummary",
    "export_sarif",
    "evaluate_target_url",
    "is_private_or_restricted_ip",
    "parse_ip_ambiguous",
    "audit_tool_metadata",
    "__version__",
]
