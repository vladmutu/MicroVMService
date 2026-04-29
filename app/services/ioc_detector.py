"""
ioc_detector.py - Heuristic IOC detection engine based on raw strace logs.

Analyzes raw strace and telemetry lines streamed by real_agent.py.
Applies clustering and scoring logic to detect malicious package behavior.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any


@dataclass
class IOCEvidence:
    verdict: str
    dynamic_hit: bool
    network_iocs: list[str]
    process_iocs: list[str]
    file_iocs: list[str]
    dns_iocs: list[str]
    crypto_iocs: list[str]
    raw_line_count: int
    outbound_connections: int
    suspicious_syscalls: int
    sensitive_writes: int


class DynamicIOCDetector:
    def __init__(self) -> None:
        self.network_iocs: list[str] = []
        self.process_iocs: list[str] = []
        self.file_iocs: list[str] = []
        self.dns_iocs: list[str] = []
        self.crypto_iocs: list[str] = []
        self.raw_lines: list[str] = []

        # Current phase tracking
        self.current_phase: str = "unknown"

        # Regexes for parsing
        self._PREFIX_RE = re.compile(r"^(PHASE|MARKER|AGENT|STDOUT):([^|]+)\|(.*)$")
        # strace with timestamps and -f often looks like: [pid] timestamp syscall(...) = ret
        self._STRACE_RE = re.compile(r"^(?:\s*\[pid\s+(\d+)\]\s+|\s*(\d+)\s+)?(\d+\.\d+)\s+([a-zA-Z0-9_]+)\((.*)\)\s*=\s*(.*)$")
        self._IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")

        # State tracking
        self.written_files: set[str] = set()
        self.memfd_created: set[str] = set()
        
        # Clusters
        self.network_events: list[dict] = []
        self.dns_events: list[dict] = []
        self.dropper_events: list[dict] = []
        self.persistence_events: list[dict] = []
        self.exfil_events: list[dict] = []
        self.reverse_shell_events: list[dict] = []
        
        # specific indicators
        self.anon_exec_mmap = False
        self.memfd_create_exec = False
        self.privilege_escalation = False
        self.stdio_redirect_to_socket = False
        self.obfuscated_cmdline = False
        self.hidden_file_created = False
        self.shell_spawned_by_installer = False

    def observe_line(self, line: str) -> None:
        stripped = line.strip()
        if not stripped:
            return

        self.raw_lines.append(stripped)

        # Parse prefix
        match = self._PREFIX_RE.match(stripped)
        if match:
            kind, phase_or_tag, content = match.groups()
            if kind == "MARKER":
                # MARKER:install:start -> content is state
                parts = phase_or_tag.split(":")
                if len(parts) >= 1:
                    self.current_phase = parts[0]
            elif kind == "PHASE":
                self.current_phase = phase_or_tag
                self._observe_strace(content, self.current_phase)
            elif kind == "STDOUT":
                self._observe_stdout(content, phase_or_tag)
            return

        # Fallback if no prefix
        self._observe_strace(stripped, self.current_phase)

    def observe_event(self, event: dict[str, Any]) -> None:
        pass # Compatibility only, we use observe_line now.

    def _observe_strace(self, line: str, phase: str) -> None:
        # Simple text heuristics across all lines
        if "xmrig" in line or "minerd" in line:
            self.crypto_iocs.append("crypto_miner")

        match = self._STRACE_RE.search(line)
        if not match:
            return

        pid_1, pid_2, ts, syscall, args_str, ret = match.groups()
        pid = pid_1 or pid_2 or "unknown"
        
        # Network Connect
        if syscall == "connect":
            if "AF_INET" in args_str:
                ip_match = self._IP_RE.search(args_str)
                if ip_match:
                    ip = ip_match.group(0)
                    try:
                        addr = ipaddress.ip_address(ip)
                        if not (addr.is_private or addr.is_loopback):
                            self.network_iocs.append(f"external_ip:{ip}")
                            self.network_events.append({"phase": phase, "action": "connect", "external_ip": True, "ip": ip})
                    except Exception:
                        pass
        
        # DNS
        if syscall == "sendto" and "sin_port=htons(53)" in args_str:
            self.dns_events.append({"phase": phase})
            self.dns_iocs.append("dns_query")

        # Reverse Shell (dup2)
        if syscall in ("dup2", "dup3"):
            if ("<TCP" in args_str or "<UDP" in args_str) and ("0" in args_str or "1" in args_str or "2" in args_str):
                self.stdio_redirect_to_socket = True
                self.reverse_shell_events.append({"type": "dup2_socket"})
                self.process_iocs.append("stdio_redirected_to_socket")

        # Exec
        if syscall in ("execve", "execveat"):
            if "base64" in args_str and ("-d" in args_str or "--decode" in args_str):
                self.obfuscated_cmdline = True
            if "curl " in args_str or "wget " in args_str:
                if "sh" in args_str or "bash" in args_str:
                    if phase == "install":
                        self.shell_spawned_by_installer = True
                        self.process_iocs.append("shell_download_exec")

            # Check if executing from /tmp or written files
            path = args_str.split(",")[0].strip('"')
            if path.startswith("/tmp/"):
                self.dropper_events.append({"type": "exec_from_tmp", "path": path})
                self.process_iocs.append(f"exec_from_tmp:{path}")
            if path in self.written_files:
                self.dropper_events.append({"type": "exec_recently_written", "path": path})
                self.process_iocs.append(f"exec_recently_written:{path}")
            if path in self.memfd_created:
                self.memfd_create_exec = True
                self.process_iocs.append(f"memfd_create_exec:{path}")

        # File Writes / Persistence
        if syscall in ("open", "openat", "creat"):
            if "O_WRONLY" in args_str or "O_RDWR" in args_str or "O_CREAT" in args_str:
                parts = args_str.split(",")
                if len(parts) >= 2:
                    path = parts[1].strip().strip('"') if syscall == "openat" else parts[0].strip().strip('"')
                    self.written_files.add(path)
                    
                    if "/.bashrc" in path or "/.profile" in path or "/etc/cron" in path or "/etc/rc.local" in path or "/.ssh/authorized_keys" in path:
                        self.persistence_events.append({"path": path})
                        self.file_iocs.append(f"persistence_path:{path}")
                    
                    if path.startswith(".") or "/." in path:
                        if "config" not in path:
                            self.hidden_file_created = True

        # File Reads / Exfil
        if syscall in ("open", "openat"):
            if "O_RDONLY" in args_str:
                parts = args_str.split(",")
                path = parts[1].strip().strip('"') if syscall == "openat" else parts[0].strip().strip('"')
                if "/.aws" in path or "/.ssh" in path or "/.gnupg" in path or "/etc/passwd" in path or "/etc/shadow" in path:
                    self.exfil_events.append({"path": path})
                    self.file_iocs.append(f"sensitive_file:{path}")

        # Memory mapping
        if syscall == "mmap":
            if "PROT_EXEC" in args_str and "PROT_WRITE" in args_str and "MAP_ANONYMOUS" in args_str:
                self.anon_exec_mmap = True
                self.process_iocs.append("anon_exec_mmap")

        # Memfd
        if syscall == "memfd_create":
            try:
                fd = ret.split()[0]
                # In strace, path looks like /proc/self/fd/X or we just track it conceptually
                self.memfd_created.add(fd)
            except Exception:
                pass

        # Privilege escalation
        if syscall in ("setuid", "setresuid", "setgid", "setresgid", "capset"):
            self.privilege_escalation = True
            self.process_iocs.append(f"privilege_escalation:{syscall}")

        # Ptrace
        if syscall == "ptrace":
            if "PTRACE_TRACEME" not in args_str:
                self.process_iocs.append("ptrace_other_process")

    def _observe_stdout(self, line: str, phase: str) -> None:
        if "/dev/tcp" in line or "bash -i" in line or ">& /dev/tcp" in line:
            self.reverse_shell_events.append({"type": "stdout_reverse_shell"})
            self.process_iocs.append("reverse_shell")

    def build_evidence(self) -> IOCEvidence:
        hard_file_iocs = [f for f in self.file_iocs if not f.startswith("uploaded_artifact:")]

        # Clustering Logic
        network_cluster = any(
            (e["phase"] == "install" and e.get("action") == "connect" and e.get("external_ip")) or 
            (e["phase"] == "monitor" and e.get("action") == "connect")
            for e in self.network_events
        ) or any(e["phase"] == "install" for e in self.dns_events)

        dropper_cluster = len(self.dropper_events) > 0 or self.memfd_create_exec
        persistence_cluster = len(self.persistence_events) > 0
        exfil_cluster = len(self.exfil_events) > 0 and len(self.network_events) > 0
        reverse_shell_cluster = len(self.reverse_shell_events) > 0 or self.stdio_redirect_to_socket

        risk_score = 0

        # Near-certain
        if reverse_shell_cluster: risk_score += 90
        if self.anon_exec_mmap: risk_score += 80
        if self.memfd_create_exec: risk_score += 80
        if network_cluster and any(e["phase"] == "install" for e in self.network_events): risk_score += 70
        if self.privilege_escalation: risk_score += 70
        if self.stdio_redirect_to_socket: risk_score += 90

        # High suspicion
        if dropper_cluster: risk_score += 50
        if persistence_cluster: risk_score += 60
        if exfil_cluster: risk_score += 65
        if self.obfuscated_cmdline: risk_score += 30

        # Corroborating signals
        if any(e["phase"] == "install" for e in self.dns_events): risk_score += 20
        if self.hidden_file_created: risk_score += 15
        if self.shell_spawned_by_installer: risk_score += 25

        risk_score = min(risk_score, 100)

        dynamic_hit = risk_score > 0

        if risk_score >= 70:
            verdict = "malicious"
        elif risk_score >= 30:
            verdict = "suspicious"
        else:
            verdict = "benign"

        suspicious_syscalls = len(self.process_iocs) + len(hard_file_iocs) + len(self.dns_iocs)
        sensitive_writes = len(self.persistence_events)

        outbound = sum(1 for n in self.network_iocs if n.startswith("external_ip:"))

        # Also emit standard IOCs
        # filter out duplicates
        return IOCEvidence(
            verdict=verdict,
            dynamic_hit=dynamic_hit,
            network_iocs=list(set(self.network_iocs)),
            process_iocs=list(set(self.process_iocs)),
            file_iocs=list(set(self.file_iocs)),
            dns_iocs=list(set(self.dns_iocs)),
            crypto_iocs=list(set(self.crypto_iocs)),
            raw_line_count=len(self.raw_lines),
            outbound_connections=outbound,
            suspicious_syscalls=suspicious_syscalls,
            sensitive_writes=sensitive_writes,
        )
