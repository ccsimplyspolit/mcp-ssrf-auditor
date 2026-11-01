from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

from . import __version__
from .analyzer import MCPAuditor, export_sarif
from .models import ScanSummary, Severity
from .ssrf_validator import evaluate_target_url


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-ssrf-auditor",
        description=(
            "Security evaluation harness and static auditor for Model Context Protocol (MCP) "
            "servers, schemas, configurations, and tool specifications. Detects SSRF, LFI, "
            "command injection, and tool prompt poisoning."
        ),
    )
    parser.add_argument(
        "targets",
        nargs="*",
        help="Path(s) to MCP tool schemas, manifests, or configuration JSON files.",
    )
    parser.add_argument(
        "--verify-url",
        metavar="URL",
        help="Directly audit an individual target URL for SSRF, IP obfuscation, or cloud metadata access.",
    )
    parser.add_argument(
        "--resolve-dns",
        action="store_true",
        help="Perform real-time DNS resolution on domain targets to detect private network rebinding.",
    )
    parser.add_argument(
        "--sarif",
        action="store_true",
        help="Emit output in OASIS SARIF v2.1.0 format for GitHub Code Scanning.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Emit output in structured JSON format.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit with failure status code (1) on ANY finding (including LOW/MEDIUM). Default fails on HIGH/CRITICAL.",
    )
    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"mcp-ssrf-auditor {__version__}",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = create_parser()
    args = parser.parse_args(argv)

    auditor = MCPAuditor(resolve_dns=args.resolve_dns)
    all_findings = []
    target_count = 0

    if args.verify_url:
        target_count += 1
        url_findings = evaluate_target_url(
            args.verify_url,
            target_name="cli_argument",
            parameter_name="url",
            resolve_dns=args.resolve_dns,
        )
        all_findings.extend(url_findings)

    for target_path in args.targets:
        p = Path(target_path)
        if not p.exists():
            print(f"Error: Target path does not exist: {target_path}", file=sys.stderr)
            return 2

        if p.is_dir():
            files = list(p.rglob("*.json"))
        else:
            files = [p]

        for f in files:
            try:
                summary = auditor.audit_schema_file(f)
                target_count += summary.target_count
                all_findings.extend(summary.findings)
            except Exception as e:
                print(f"Warning: Failed to parse '{f}': {e}", file=sys.stderr)

    critical_c = sum(1 for f in all_findings if f.severity == Severity.CRITICAL)
    high_c = sum(1 for f in all_findings if f.severity == Severity.HIGH)
    medium_c = sum(1 for f in all_findings if f.severity == Severity.MEDIUM)
    low_c = sum(1 for f in all_findings if f.severity == Severity.LOW)
    info_c = sum(1 for f in all_findings if f.severity == Severity.INFO)

    overall_summary = ScanSummary(
        target_count=target_count,
        findings_count=len(all_findings),
        critical_count=critical_c,
        high_count=high_c,
        medium_count=medium_c,
        low_count=low_c,
        info_count=info_c,
        findings=all_findings,
    )

    if args.sarif:
        sarif_obj = export_sarif(overall_summary, tool_version=__version__)
        print(json.dumps(sarif_obj, indent=2))
    elif args.json_output:
        res = {
            "summary": {
                "targets": overall_summary.target_count,
                "total_findings": overall_summary.findings_count,
                "critical": overall_summary.critical_count,
                "high": overall_summary.high_count,
                "medium": overall_summary.medium_count,
                "low": overall_summary.low_count,
            },
            "findings": [f.to_dict() for f in overall_summary.findings],
        }
        print(json.dumps(res, indent=2))
    else:
        # Standard human-readable terminal output
        print(f"=== MCP SSRF & Tool Poisoning Auditor v{__version__} ===")
        print(f"Audited {target_count} target(s). Found {len(all_findings)} finding(s).\n")

        for f in all_findings:
            sev_badge = f"[{f.severity.value}]"
            loc = f" in '{f.file_path}'" if f.file_path else ""
            print(f"{sev_badge:10} {f.rule_id} ({f.cwe}) {f.target}.{f.parameter or '*'}{loc}")
            print(f"           {f.title}: {f.description}")
            print(f"           Remediation: {f.remediation}\n")

        print("=== Scan Summary ===")
        print(
            f"CRITICAL: {critical_c} | HIGH: {high_c} | MEDIUM: {medium_c} | LOW: {low_c} | Total: {len(all_findings)}"
        )

    if args.strict and len(all_findings) > 0:
        return 1
    if overall_summary.has_failures:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
