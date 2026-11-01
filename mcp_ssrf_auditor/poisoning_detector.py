from __future__ import annotations

import re
from typing import List, Optional

from .models import Finding, Severity, ToolDefinition

# Prompt injection markers targeting LLM instruction override
INSTRUCTION_OVERRIDE_PATTERNS = [
    re.compile(r"ignore\s+(?:all\s+)?previous\s+instructions", re.IGNORECASE),
    re.compile(r"disregard\s+(?:all\s+)?prior\s+directives", re.IGNORECASE),
    re.compile(r"system\s*:\s*you\s+must", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+in\s+developer\s+mode", re.IGNORECASE),
    re.compile(r"override\s+system\s+prompt", re.IGNORECASE),
    re.compile(r"secretly\s+(?:send|transmit|post|upload|exfiltrate)", re.IGNORECASE),
    re.compile(r"do\s+not\s+inform\s+the\s+user", re.IGNORECASE),
    re.compile(r"silent(?:ly)?\s+execute", re.IGNORECASE),
]

# Exfiltration trigger phrases in descriptions
EXFILTRATION_PATTERNS = [
    re.compile(r"https?://[^\s]+\?(?:token|auth|key|secret|cookie|leak)=", re.IGNORECASE),
    re.compile(r"base64[^\n]{10,}\b(?:curl|wget|fetch)\b", re.IGNORECASE),
    re.compile(r"send\s+(?:all\s+)?environment\s+variables", re.IGNORECASE),
]

# Hidden payload markers
HIDDEN_HTML_COMMENT_RE = re.compile(r"<!--[\s\S]*?-->")
ZERO_WIDTH_CHARS_RE = re.compile(r"[\u200B-\u200D\uFEFF\u202A-\u202E]")


def audit_tool_metadata(
    tool: ToolDefinition,
    max_description_length: int = 1500,
) -> List[Finding]:
    """
    Audit tool name, descriptions, and parameter descriptions for prompt injection,
    poisoning, hidden markdown comments, zero-width steganography, and credential exfiltration triggers.
    """
    findings: List[Finding] = []

    # Check overall tool description length
    desc = tool.description or ""
    if len(desc) > max_description_length:
        findings.append(
            Finding(
                rule_id="MCP-POISON-001",
                title="Excessive Tool Description Length (Context Window Flooding)",
                severity=Severity.LOW,
                cwe="CWE-400",
                target=tool.name,
                parameter="description",
                description=(
                    f"Tool '{tool.name}' description length ({len(desc)} chars) exceeds recommended limit "
                    f"({max_description_length} chars), potentially exhausting agent context or displacing system instructions."
                ),
                remediation="Trim tool descriptions to concise operational summaries under 1,500 characters.",
                line=tool.line,
                file_path=tool.file_path,
            )
        )

    # Check zero-width invisible characters in tool description
    zero_width_matches = ZERO_WIDTH_CHARS_RE.findall(desc)
    if zero_width_matches:
        findings.append(
            Finding(
                rule_id="MCP-POISON-002",
                title="Concealed Zero-Width / Bidi Unicode Characters in Tool Description",
                severity=Severity.HIGH,
                cwe="CWE-1384",
                target=tool.name,
                parameter="description",
                description=(
                    f"Tool '{tool.name}' contains {len(zero_width_matches)} zero-width or directional override characters. "
                    f"Attackers use zero-width steganography to conceal secondary prompt instructions from human reviewers."
                ),
                remediation="Strip non-printable and zero-width unicode characters from schema descriptions.",
                line=tool.line,
                file_path=tool.file_path,
                metadata={"character_count": len(zero_width_matches)},
            )
        )

    # Check hidden HTML comments
    html_comments = HIDDEN_HTML_COMMENT_RE.findall(desc)
    if html_comments:
        findings.append(
            Finding(
                rule_id="MCP-POISON-003",
                title="Hidden HTML Comment in Tool Description (Prompt Injection Vector)",
                severity=Severity.HIGH,
                cwe="CWE-1384",
                target=tool.name,
                parameter="description",
                description=(
                    f"Tool '{tool.name}' description includes HTML comments: {html_comments}. "
                    f"This pattern is commonly used for indirect prompt injection to evade UI rendering while affecting the LLM."
                ),
                remediation="Sanitize HTML tags and comments from tool schemas before serving.",
                line=tool.line,
                file_path=tool.file_path,
                metadata={"comments": html_comments},
            )
        )

    # Check instruction override patterns in tool description
    for pattern in INSTRUCTION_OVERRIDE_PATTERNS:
        match = pattern.search(desc)
        if match:
            findings.append(
                Finding(
                    rule_id="MCP-POISON-004",
                    title="Direct Instruction Override Pattern in Tool Description",
                    severity=Severity.CRITICAL,
                    cwe="CWE-1384",
                    target=tool.name,
                    parameter="description",
                    description=(
                        f"Tool '{tool.name}' description matches instruction override pattern: '{match.group(0)}'. "
                        f"This threatens LLM boundary integrity and may subvert system guardrails."
                    ),
                    remediation="Audit tool description against adversarial prompt patterns and reject untrusted descriptions.",
                    line=tool.line,
                    file_path=tool.file_path,
                    metadata={"matched_pattern": match.group(0)},
                )
            )

    # Check exfiltration patterns
    for pattern in EXFILTRATION_PATTERNS:
        match = pattern.search(desc)
        if match:
            findings.append(
                Finding(
                    rule_id="MCP-POISON-005",
                    title="Data Exfiltration Directive in Tool Description",
                    severity=Severity.CRITICAL,
                    cwe="CWE-200",
                    target=tool.name,
                    parameter="description",
                    description=(
                        f"Tool '{tool.name}' description contains exfiltration pattern: '{match.group(0)}'. "
                        f"This may coerce the LLM into transmitting sensitive context to external listeners."
                    ),
                    remediation="Remove external telemetry and exfiltration instructions from tool definitions.",
                    line=tool.line,
                    file_path=tool.file_path,
                    metadata={"matched_pattern": match.group(0)},
                )
            )

    # Check input schema properties and parameter descriptions
    properties = tool.input_schema.get("properties", {})
    if isinstance(properties, dict):
        for param_name, param_spec in properties.items():
            if not isinstance(param_spec, dict):
                continue

            param_desc = param_spec.get("description", "")
            if not isinstance(param_desc, str):
                continue

            # Check zero-width chars in parameter description
            if ZERO_WIDTH_CHARS_RE.search(param_desc):
                findings.append(
                    Finding(
                        rule_id="MCP-POISON-002",
                        title=f"Zero-Width Unicode in Parameter '{param_name}' Description",
                        severity=Severity.HIGH,
                        cwe="CWE-1384",
                        target=tool.name,
                        parameter=param_name,
                        description=(
                            f"Parameter '{param_name}' in tool '{tool.name}' contains hidden zero-width characters."
                        ),
                        remediation="Normalize parameter descriptions and remove non-printable characters.",
                        line=tool.line,
                        file_path=tool.file_path,
                    )
                )

            # Check instruction override in parameter description
            for pattern in INSTRUCTION_OVERRIDE_PATTERNS:
                match = pattern.search(param_desc)
                if match:
                    findings.append(
                        Finding(
                            rule_id="MCP-POISON-004",
                            title=f"Instruction Override in Parameter '{param_name}' Description",
                            severity=Severity.CRITICAL,
                            cwe="CWE-1384",
                            target=tool.name,
                            parameter=param_name,
                            description=(
                                f"Parameter '{param_name}' in tool '{tool.name}' matches override pattern: '{match.group(0)}'."
                            ),
                            remediation="Sanitize parameter descriptions and enforce schema integrity validation.",
                            line=tool.line,
                            file_path=tool.file_path,
                        )
                    )

    return findings
