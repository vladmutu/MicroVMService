"""
ioc_detector.py — Host-side Indicator of Compromise detector.

Scans raw strace output and process logs streamed from the guest VM.
Every line from vsock port 7002 is fed through `observe_line()`.
After the VM finishes, `build_evidence()` produces a structured report.

The guest agent is a *pure data collector* — it emits raw events and the
host interprets them.  This prevents in-VM malware from tampering with
the verdict.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class IOCEvidence:
    """Structured evidence produced by the detector."""

    verdict: str                    # "malicious" | "suspicious" | "benign"
    dynamic_hit: bool
    network_iocs: list[str]
    process_iocs: list[str]
    file_iocs: list[str]
    dns_iocs: list[str]
    crypto_iocs: list[str]
    raw_line_count: int

    # Counts used for risk scoring
    outbound_connections: int = 0
    suspicious_syscalls: int = 0
    sensitive_writes: int = 0


class DynamicIOCDetector:
    """
    Regex-based strace/log line analyser.

    Detects:
    • Public IP connections (non-RFC1918/loopback/link-local)
    • Suspicious ports (4444 reverse-shell, 6667 IRC C&C, etc.)
    • Sensitive file opens (/etc/shadow, .ssh/authorized_keys, crontabs …)
    • Shell-based download/exec chains (wget | curl | chmod +x | base64 -d)
    • DNS exfiltration patterns (very long subdomains)
    • Cryptocurrency miner process names / arguments
    • Reverse shell patterns (bash -i, /dev/tcp)
    """

    _SUSPICIOUS_PORTS = {4444, 5555, 6667, 9001, 9050, 31337}

    _PUBLIC_IP_RE = re.compile(
        r'(?:'
        r'sin_addr=inet_addr\("(?P<ip2>\d{1,3}(?:\.\d{1,3}){3})"\)'
        r'|'
        r'inet_pton\([^)]*,\s*"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"'
        r'|'
        r'(?:connect|sendto)\([^\n]*?(?<=[^0-9])(?P<ip3>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
        r')',
    )

    _PORT_RE = re.compile(r"htons\((\d+)\)|sin_port=htons\((\d+)\)")

    _SENSITIVE_OPEN_RE = re.compile(
        r'open(?:at)?\([^\n]*"(?P<path>'
        r'(?:/etc/cron[^\"\s]*'
        r'|/etc/shadow'
        r'|/etc/passwd'
        r'|/etc/sudoers'
        r'|/etc/ld\.so\.preload'
        r'|/root/\.ssh/authorized_keys'
        r'|~/?\.\bssh\b/authorized_keys'
        r'|[^\"\s]*/\.bashrc'
        r'|[^\"\s]*/\.profile'
        r'|[^\"\s]*/\.bash_profile'
        r'|/proc/self/exe'
        r'))"',
        re.IGNORECASE,
    )

    _SUSPICIOUS_EXEC_RE = re.compile(
        r'execve\([^\n]*"(?:/bin/sh|/bin/bash|/bin/dash)"'
        r'[^\n]*-c[^\n]*'
        r'(wget|curl|chmod\s+\+x|base64(?:\s+-d|\s+--decode)?|nc\s|ncat\s|socat\s)',
        re.IGNORECASE,
    )

    _REVERSE_SHELL_RE = re.compile(
        r'(?:bash\s+-i|/dev/tcp/|/dev/udp/|mkfifo|nc\s+-[^\n]*-e\s|ncat\s.*--exec)',
        re.IGNORECASE,
    )

    _DNS_EXFIL_RE = re.compile(
        r'getaddrinfo\([^\n]*"(?P<domain>[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
        r'(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*)"',
    )

    _CRYPTO_MINER_RE = re.compile(
        r'(?:xmrig|minerd|cpuminer|stratum\+tcp://|stratum\+ssl://|'
        r'monero|cryptonight|ethash|pool\.minergate)',
        re.IGNORECASE,
    )

    _DATA_STAGING_RE = re.compile(
        r'(?:tar\s+c[^\n]*\|.*(?:curl|wget|nc)|'
        r'zip\s+-r[^\n]*/tmp/|'
        r'base64\s+[^\n]*/etc/|'
        r'cat\s+/etc/passwd)',
        re.IGNORECASE,
    )

    def __init__(self) -> None:
        self.network_iocs: list[str] = []
        self.process_iocs: list[str] = []
        self.file_iocs: list[str] = []
        self.dns_iocs: list[str] = []
        self.crypto_iocs: list[str] = []
        self.raw_lines: list[str] = []

    def observe_line(self, line: str) -> None:
        """Feed a single log/strace line for IOC analysis."""
        self.raw_lines.append(line)

        if "connect(" in line or "sendto(" in line:
            self._observe_network(line)
        if "execve(" in line:
            self._observe_exec(line)
        if "open(" in line or "openat(" in line:
            self._observe_file(line)
        if "getaddrinfo(" in line:
            self._observe_dns(line)

        # Check every line for crypto/reverse-shell patterns
        self._observe_crypto(line)
        self._observe_reverse_shell(line)
        self._observe_data_staging(line)

    # ── Network ───────────────────────────────────────────────────────

    def _observe_network(self, line: str) -> None:
        # Check for public IPs
        for match in self._PUBLIC_IP_RE.finditer(line):
            ip_text = match.group("ip") or match.group("ip2") or match.group("ip3")
            if ip_text and self._is_public_ip(ip_text):
                ioc = f"public_ip:{ip_text}"
                if ioc not in self.network_iocs:
                    self.network_iocs.append(ioc)
                return

        # Check for suspicious ports
        for match in self._PORT_RE.finditer(line):
            port_text = match.group(1) or match.group(2)
            if not port_text:
                continue
            try:
                port = int(port_text)
            except ValueError:
                continue
            if port in self._SUSPICIOUS_PORTS:
                ioc = f"suspicious_port:{port}"
                if ioc not in self.network_iocs:
                    self.network_iocs.append(ioc)
                return

    # ── Process / exec ────────────────────────────────────────────────

    def _observe_exec(self, line: str) -> None:
        if self._SUSPICIOUS_EXEC_RE.search(line):
            self.process_iocs.append(f"suspicious_exec:{line[:200]}")

    def _observe_reverse_shell(self, line: str) -> None:
        if self._REVERSE_SHELL_RE.search(line):
            ioc = f"reverse_shell:{line[:200]}"
            if ioc not in self.process_iocs:
                self.process_iocs.append(ioc)

    # ── File access ───────────────────────────────────────────────────

    def _observe_file(self, line: str) -> None:
        match = self._SENSITIVE_OPEN_RE.search(line)
        if match:
            path = match.group("path")
            ioc = f"sensitive_file:{path}"
            if ioc not in self.file_iocs:
                self.file_iocs.append(ioc)

    # ── DNS ───────────────────────────────────────────────────────────

    def _observe_dns(self, line: str) -> None:
        match = self._DNS_EXFIL_RE.search(line)
        if match:
            domain = match.group("domain")
            # Flag very long subdomains (possible exfil) or known bad TLDs
            labels = domain.split(".")
            if any(len(label) > 40 for label in labels) or len(labels) > 6:
                ioc = f"dns_exfil_suspect:{domain}"
                if ioc not in self.dns_iocs:
                    self.dns_iocs.append(ioc)

    # ── Crypto mining ─────────────────────────────────────────────────

    def _observe_crypto(self, line: str) -> None:
        if self._CRYPTO_MINER_RE.search(line):
            ioc = f"crypto_miner:{line[:200]}"
            if ioc not in self.crypto_iocs:
                self.crypto_iocs.append(ioc)

    # ── Data staging / exfiltration ───────────────────────────────────

    def _observe_data_staging(self, line: str) -> None:
        if self._DATA_STAGING_RE.search(line):
            ioc = f"data_staging:{line[:200]}"
            if ioc not in self.process_iocs:
                self.process_iocs.append(ioc)

    # ── Utility ───────────────────────────────────────────────────────

    @staticmethod
    def _is_public_ip(ip_text: str) -> bool:
        try:
            address = ipaddress.ip_address(ip_text)
        except ValueError:
            return False
        return not (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_reserved
            or address.is_unspecified
        )

    # ── Evidence builder ──────────────────────────────────────────────

    def build_evidence(self) -> IOCEvidence:
        """
        Compute the final verdict from all observed IOCs.

        Verdict logic:
            malicious  — any network, process, file, or crypto IOC found
            suspicious — DNS exfil suspects only (could be false positive)
            benign     — no IOCs detected
        """
        has_hard_iocs = bool(
            self.network_iocs
            or self.process_iocs
            or self.file_iocs
            or self.crypto_iocs
        )
        has_soft_iocs = bool(self.dns_iocs)

        if has_hard_iocs:
            verdict = "malicious"
        elif has_soft_iocs:
            verdict = "suspicious"
        else:
            verdict = "benign"

        return IOCEvidence(
            verdict=verdict,
            dynamic_hit=has_hard_iocs or has_soft_iocs,
            network_iocs=list(self.network_iocs),
            process_iocs=list(self.process_iocs),
            file_iocs=list(self.file_iocs),
            dns_iocs=list(self.dns_iocs),
            crypto_iocs=list(self.crypto_iocs),
            raw_line_count=len(self.raw_lines),
            outbound_connections=len(self.network_iocs),
            suspicious_syscalls=len(self.process_iocs) + len(self.file_iocs),
            sensitive_writes=len(self.file_iocs),
        )
