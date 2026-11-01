from __future__ import annotations

import ipaddress
import re
import socket
from typing import List, Optional, Set, Tuple
from urllib.parse import urlparse

from .models import Finding, Severity

# Forbidden non-HTTP schemes often abused in SSRF / internal pivots
FORBIDDEN_SCHEMES: Set[str] = {
    "file",
    "gopher",
    "dict",
    "ldap",
    "ldaps",
    "tftp",
    "data",
    "jar",
    "expect",
    "php",
    "glob",
}

# Cloud metadata services and hypervisor endpoints
CLOUD_METADATA_HOSTS: Set[str] = {
    "169.254.169.254",
    "instance-data",
    "metadata.google.internal",
    "metadata.internal",
    "metadata.tencentyun.com",
    "100.100.100.200",
}

# Regex to detect octal, hex, or decimal integer IP encodings
DECIMAL_IP_RE = re.compile(r"^\d{8,11}$")
HEX_IP_RE = re.compile(r"^0x[0-9a-fA-F]{1,8}$")
OCTAL_OCTET_RE = re.compile(r"^0[0-7]+$")


def parse_ip_ambiguous(host: str) -> Optional[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """
    Attempt to parse ambiguous IP encodings including decimal, hex, octal,
    bracketed IPv6, and IPv4-mapped IPv6.
    """
    clean_host = host.strip().strip("[]").rstrip(".")
    if not clean_host:
        return None

    # Standard direct parse
    try:
        return ipaddress.ip_address(clean_host)
    except ValueError:
        pass

    # Decimal integer format e.g. 2130706433 -> 127.0.0.1
    if DECIMAL_IP_RE.match(clean_host):
        try:
            val = int(clean_host, 10)
            if 0 <= val <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(val)
        except ValueError:
            pass

    # Hex integer format e.g. 0x7f000001 -> 127.0.0.1
    if HEX_IP_RE.match(clean_host):
        try:
            val = int(clean_host, 16)
            if 0 <= val <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(val)
        except ValueError:
            pass

    # Octal/Mixed octets e.g. 0177.0.0.1 or 0177.0.0.01
    parts = clean_host.split(".")
    if len(parts) == 4:
        try:
            octets = []
            for part in parts:
                if OCTAL_OCTET_RE.match(part):
                    octets.append(int(part, 8))
                elif part.startswith("0x") or part.startswith("0X"):
                    octets.append(int(part, 16))
                elif part.isdigit():
                    octets.append(int(part, 10))
                else:
                    return None
            if all(0 <= o <= 255 for o in octets):
                return ipaddress.IPv4Address(bytes(octets))
        except (ValueError, OverflowError):
            pass

    return None


def is_private_or_restricted_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> Tuple[bool, str]:
    """Check if an IP address belongs to loopback, private, link-local, multicast, or reserved ranges."""
    if ip.is_loopback:
        return True, "Loopback address (127.0.0.0/8 or ::1)"
    if ip.is_private:
        return True, "RFC 1918 / ULA private network range"
    if ip.is_link_local:
        return True, "Link-local / Cloud metadata range (169.254.0.0/16 or fe80::/10)"
    if ip.is_multicast:
        return True, "Multicast address range"
    if ip.is_reserved:
        return True, "IETF / IANA reserved IP range"
    if ip.is_unspecified:
        return True, "Unspecified address (0.0.0.0 or ::)"

    # Check IPv4-mapped IPv6 explicitly
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        return is_private_or_restricted_ip(ip.ipv4_mapped)

    return False, ""


def evaluate_target_url(
    url_str: str,
    target_name: str,
    parameter_name: str = "url",
    resolve_dns: bool = False,
    file_path: Optional[str] = None,
    line: Optional[int] = None,
) -> List[Finding]:
    """
    Rigorously audit a target URL for SSRF vulnerabilities, scheme abuse,
    cloud metadata access, and bypass techniques (trailing dots, localhost variations, IP formats).
    """
    findings: List[Finding] = []

    try:
        parsed = urlparse(url_str.strip())
    except Exception as exc:
        findings.append(
            Finding(
                rule_id="MCP-URL-001",
                title="Malformed URL in Tool Argument",
                severity=Severity.HIGH,
                cwe="CWE-20",
                target=target_name,
                parameter=parameter_name,
                description=f"Tool argument '{parameter_name}' contains an unparseable URL '{url_str}': {exc}",
                remediation="Validate URL structure using RFC 3986 compliant URI parser before consumption.",
                line=line,
                file_path=file_path,
            )
        )
        return findings

    scheme = parsed.scheme.lower()
    if not scheme:
        findings.append(
            Finding(
                rule_id="MCP-URL-002",
                title="Missing Protocol Scheme in URL",
                severity=Severity.MEDIUM,
                cwe="CWE-20",
                target=target_name,
                parameter=parameter_name,
                description=f"URL '{url_str}' lacks an explicit scheme (e.g., https://), permitting protocol smuggling.",
                remediation="Enforce explicit 'https' or 'http' scheme requirement in parameter schema.",
                line=line,
                file_path=file_path,
            )
        )
        return findings

    # Check forbidden non-HTTP schemes
    if scheme in FORBIDDEN_SCHEMES:
        findings.append(
            Finding(
                rule_id="MCP-SSRF-001",
                title=f"Forbidden High-Risk Protocol Scheme ({scheme}://)",
                severity=Severity.CRITICAL,
                cwe="CWE-918",
                target=target_name,
                parameter=parameter_name,
                description=(
                    f"Tool argument '{parameter_name}' permits high-risk scheme '{scheme}://' "
                    f"in target '{url_str}', enabling local file disclosure or protocol pivoting."
                ),
                remediation="Restrict permitted schemes to an allowlist: ['https', 'http'].",
                line=line,
                file_path=file_path,
                metadata={"scheme": scheme, "url": url_str},
            )
        )

    hostname = parsed.hostname or ""
    hostname_lower = hostname.lower()

    # Trailing dot detection (GHSA-qm7x-j9xp-x3gv pattern)
    if hostname.endswith("."):
        findings.append(
            Finding(
                rule_id="MCP-SSRF-002",
                title="Trailing Dot Hostname SSRF Bypass Pattern",
                severity=Severity.HIGH,
                cwe="CWE-918",
                target=target_name,
                parameter=parameter_name,
                description=(
                    f"Hostname '{hostname}' in '{url_str}' contains a trailing FQDN dot. "
                    f"Poorly implemented domain regexes fail to match trailing-dot internal hosts (e.g. 'localhost.'), "
                    f"bypassing URL filters while resolving to internal targets."
                ),
                remediation="Normalize hostname with `host.rstrip('.')` before applying domain allowlists or IP checks.",
                line=line,
                file_path=file_path,
                metadata={"hostname": hostname, "url": url_str},
            )
        )

    # Localhost alias check
    normalized_host = hostname_lower.rstrip(".")
    if (
        normalized_host == "localhost"
        or normalized_host.endswith(".localhost")
        or normalized_host.endswith(".local")
        or normalized_host.endswith(".internal")
        or normalized_host.endswith(".nip.io") and "127.0.0.1" in normalized_host
    ):
        findings.append(
            Finding(
                rule_id="MCP-SSRF-003",
                title="Direct Localhost / Internal Domain Reference",
                severity=Severity.CRITICAL,
                cwe="CWE-918",
                target=target_name,
                parameter=parameter_name,
                description=(
                    f"Target URL '{url_str}' specifies internal domain or localhost alias '{normalized_host}', "
                    f"allowing arbitrary requests against internal loopback services."
                ),
                remediation="Enforce destination allowlists and block internal / localhost domains before invocation.",
                line=line,
                file_path=file_path,
                metadata={"hostname": normalized_host, "url": url_str},
            )
        )

    # Cloud metadata check
    if normalized_host in CLOUD_METADATA_HOSTS:
        findings.append(
            Finding(
                rule_id="MCP-SSRF-004",
                title="Cloud Metadata Service Endpoint Target",
                severity=Severity.CRITICAL,
                cwe="CWE-918",
                target=target_name,
                parameter=parameter_name,
                description=(
                    f"Target URL '{url_str}' directly addresses cloud instance metadata service ('{normalized_host}'), "
                    f"exposing instance IAM tokens, SSH credentials, and environment configuration."
                ),
                remediation="Hard-block 169.254.169.254, metadata.google.internal, and link-local ranges at network layer.",
                line=line,
                file_path=file_path,
                metadata={"hostname": normalized_host, "url": url_str},
            )
        )

    # Ambiguous / Hex / Octal / Decimal IP check
    parsed_ip = parse_ip_ambiguous(hostname)
    if parsed_ip is not None:
        is_restricted, reason = is_private_or_restricted_ip(parsed_ip)
        if is_restricted:
            findings.append(
                Finding(
                    rule_id="MCP-SSRF-005",
                    title="Private or Restricted IP Address in Target URL",
                    severity=Severity.CRITICAL,
                    cwe="CWE-918",
                    target=target_name,
                    parameter=parameter_name,
                    description=(
                        f"URL target resolves directly to restricted IP {parsed_ip} ({reason}). "
                        f"Permitting outgoing connections to this destination risks intranet traversal."
                    ),
                    remediation="Reject private, link-local, loopback, and broadcast IP ranges prior to client dispatch.",
                    line=line,
                    file_path=file_path,
                    metadata={"ip": str(parsed_ip), "reason": reason, "url": url_str},
                )
            )

    # Optional DNS resolution to detect rebinding or internal domain resolution
    if resolve_dns and normalized_host and parsed_ip is None:
        try:
            addr_info = socket.getaddrinfo(normalized_host, None)
            resolved_ips = {item[4][0] for item in addr_info}
            for rip_str in resolved_ips:
                try:
                    rip = ipaddress.ip_address(rip_str)
                    is_res, res_reason = is_private_or_restricted_ip(rip)
                    if is_res:
                        findings.append(
                            Finding(
                                rule_id="MCP-SSRF-006",
                                title="DNS Resolution Yields Private/Restricted IP (SSRF)",
                                severity=Severity.CRITICAL,
                                cwe="CWE-918",
                                target=target_name,
                                parameter=parameter_name,
                                description=(
                                    f"Domain '{normalized_host}' resolved to restricted IP {rip} ({res_reason}). "
                                    f"This exposes the server to DNS rebinding or internal domain resolution SSRF."
                                ),
                                remediation="Resolve host immediately prior to socket connection and verify IP range on every hop.",
                                line=line,
                                file_path=file_path,
                                metadata={"resolved_ip": str(rip), "hostname": normalized_host},
                            )
                        )
                except ValueError:
                    continue
        except socket.gaierror:
            pass

    return findings
