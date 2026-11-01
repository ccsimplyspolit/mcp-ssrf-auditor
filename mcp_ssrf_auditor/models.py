from __future__ import annotations

import dataclasses
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclasses.dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    cwe: str
    target: str
    parameter: Optional[str]
    description: str
    remediation: str
    line: Optional[int] = None
    file_path: Optional[str] = None
    metadata: Dict[str, Any] = dataclasses.field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "cwe": self.cwe,
            "target": self.target,
            "parameter": self.parameter,
            "description": self.description,
            "remediation": self.remediation,
            "line": self.line,
            "file_path": self.file_path,
            "metadata": self.metadata,
        }


@dataclasses.dataclass
class ToolDefinition:
    name: str
    description: str
    input_schema: Dict[str, Any]
    file_path: str = "<memory>"
    line: int = 1


@dataclasses.dataclass
class ResourceDefinition:
    uri: str
    name: Optional[str] = None
    mime_type: Optional[str] = None
    description: Optional[str] = None
    file_path: str = "<memory>"
    line: int = 1


@dataclasses.dataclass
class ScanSummary:
    target_count: int
    findings_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    findings: List[Finding]

    @property
    def has_failures(self) -> bool:
        return (self.critical_count + self.high_count) > 0
