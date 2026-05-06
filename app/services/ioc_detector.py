"""
ioc_detector.py - Heuristic IOC detection engine based on raw strace logs.

Analyzes raw strace and telemetry lines streamed by real_agent.py.
Applies clustering, process-tree analysis, phase-weighted scoring, and
CDN/pip whitelisting to detect malicious package behaviour with low
false-positive rate.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Phase multipliers: install-time activity is most suspicious
_PHASE_MULT: dict[str, float] = {
    "install": 1.5,
    "exec":    1.0,
    "monitor": 0.6,
    "unknown": 0.8,
}

# Ports that are almost never used by legitimate package operations
_SUSPICIOUS_PORTS: frozenset[int] = frozenset({
    4444, 6666, 1337, 31337, 8888, 9999, 2222, 5555,
    1234, 7777, 9001, 6660, 6667, 6697,  # IRC / C2
})

# Known-safe CDN ranges (PyPI via Fastly, npm via Cloudflare/Akamai)
_SAFE_NETS: list[ipaddress.IPv4Network] = [
    ipaddress.ip_network("151.101.0.0/16"),   # Fastly (files.pythonhosted.org)
    ipaddress.ip_network("104.16.0.0/13"),    # Cloudflare (registry.npmjs.org)
    ipaddress.ip_network("104.24.0.0/14"),    # Cloudflare
    ipaddress.ip_network("2.21.68.0/24"),     # Akamai
    ipaddress.ip_network("2.21.69.0/24"),     # Akamai
    ipaddress.ip_network("23.235.32.0/20"),   # Fastly
    ipaddress.ip_network("199.232.0.0/16"),   # Fastly
    ipaddress.ip_network("8.8.8.0/24"),       # Google DNS
    ipaddress.ip_network("8.8.4.0/24"),       # Google DNS secondary
    ipaddress.ip_network("1.1.1.0/24"),       # Cloudflare DNS
    ipaddress.ip_network("1.0.0.0/24"),       # Cloudflare DNS secondary
    ipaddress.ip_network("54.182.0.0/16"),    # CloudFront
    ipaddress.ip_network("52.84.0.0/14"),     # CloudFront
]

# Legitimate pip temp paths — executions from these are expected
_PIP_TMP_RE = re.compile(
    r"^/tmp/pip-(?:build|install|req-build|unpack|record|wheel|download|"
    r"standalone|collect)-"
)

# Analysis infrastructure paths — our own tools running inside /tmp/analysis/
_ANALYSIS_TMP_PREFIXES: tuple[str, ...] = (
    "/tmp/analysis/venv/",
    "/tmp/analysis/npm-project/node_modules/",
)

# DNS label substrings expected during normal package registry operations
_SAFE_REGISTRY_DNS: tuple[str, ...] = (
    "pypi",         # pypi.org
    "pythonhosted", # files.pythonhosted.org
    "npmjs",        # registry.npmjs.org, cdn.npmjs.org
)

# System utilities that setup.py / npm install scripts should never need.
# NOTE: uname and lsb_release are intentionally excluded — pip itself calls
# them on every install for platform-tag detection, so they fire for every
# package and have no discriminative value.
_RECON_COMMANDS: frozenset[str] = frozenset({
    "id", "whoami", "hostname", "getconf",
})

# Netlink protocols that are completely safe when used with SOCK_RAW.
# NETLINK_ROUTE: routing/interface queries (libc getifaddrs, getaddrinfo)
# NETLINK_SOCK_DIAG: socket diagnostics (ss, netstat)
_SAFE_NETLINK_PROTOS: frozenset[str] = frozenset({"NETLINK_ROUTE", "NETLINK_SOCK_DIAG"})

# DDNS hostname labels checked against DNS wire-format payload in sendto args_str.
# DNS wire format uses length-prefixed labels with NO dots, so "duckdns.org" as a
# substring would never match — we match the distinctive hostname label only.
_DDNS_DOMAINS: tuple[str, ...] = (
    "no-ip", "afraid", "duckdns", "ddns",
    "dynu", "changeip", "hopto", "servebeer",
)

_PORT_RE = re.compile(r"sin_port=htons\((\d+)\)")
_IP_RE   = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")

# Paths written to during install that indicate persistence or credential theft
_PERSIST_PATHS: tuple[str, ...] = (
    "/.bashrc", "/.bash_profile", "/.profile", "/.zshrc",
    "/etc/cron", "/etc/rc.local", "/etc/init.d/",
    "/.ssh/authorized_keys", "/var/spool/cron", "crontab",
    "/.config/autostart",
)

_SENSITIVE_READ_PATHS: tuple[str, ...] = (
    "/.aws/", "/.ssh/", "/.gnupg/",
    "/etc/passwd", "/etc/shadow", "/etc/sudoers",
    "/.config/gcloud", "/.kube/config",
    "/.npmrc", "/.pypirc",
)

# Root-level directory names that are normal system paths (not suspicious)
_SAFE_ROOT_DIRS: frozenset[str] = frozenset({
    "tmp", "proc", "sys", "dev", "run", "mnt", "media",
    "home", "var", "usr", "opt", "lib", "lib64", "bin", "sbin",
    "boot", "etc", "srv", "snap", "root",
})

# Phrases in install stdout that indicate anti-analysis / sandbox evasion
_ANTI_ANALYSIS_PHRASES: tuple[str, ...] = (
    "trick system", "are you running this on",
    "sandbox detected", "vm detected", "analysis environment",
    "virtual machine", "debugger detected",
)

# Matches "Created '/path'" or "Writing to '/path'" in package stdout
_STDOUT_FILE_WRITE_RE = re.compile(
    r"(?:[Cc]reated?|[Ww]riting(?: to)?)\s+['\"]?(/[^\s'\">,]+)"
)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class IOCEvent:
    """A single detected IOC with full context for DB storage."""
    phase: str
    category: str        # network | process | file | dns | crypto | memory
    subcategory: str     # e.g. external_ip, exec_from_tmp, persistence_path
    score_contribution: int
    detail: dict[str, Any] = field(default_factory=dict)
    raw_line: str = ""


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
    ioc_events: list[IOCEvent] = field(default_factory=list)
    risk_score: int = 0


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------

class DynamicIOCDetector:

    def __init__(self) -> None:
        # IOC lists (string-form, for backwards compat with existing callers)
        self.network_iocs: list[str] = []
        self.process_iocs: list[str] = []
        self.file_iocs:    list[str] = []
        self.dns_iocs:     list[str] = []
        self.crypto_iocs:  list[str] = []
        self.raw_lines:    list[str] = []

        # Structured IOC events (for DB storage)
        self.ioc_events: list[IOCEvent] = []

        # Current phase
        self.current_phase: str = "unknown"

        # ── Regexes ────────────────────────────────────────────────────
        self._PREFIX_RE = re.compile(r"^(PHASE|MARKER|AGENT|STDOUT):([^|]+)\|(.*)$")

        # strace -f --timestamps=unix,us produces:
        #   <pid>   <ts.us> syscall(args) = ret
        # or (single-threaded, no -f):
        #   <ts.us> syscall(args) = ret
        self._STRACE_RE = re.compile(
            r"^\s*(?:(?P<pid>\d+)\s+)?(?P<ts>\d+\.\d+)\s+"
            r"(?P<syscall>[a-zA-Z0-9_]+)\((?P<args>.*)\)\s*=\s*(?P<ret>.*)$"
        )

        # ── State ──────────────────────────────────────────────────────
        self.written_files: set[str] = set()
        self.memfd_created: set[str] = set()
        self.recon_seen:   set[str] = set()  # dedup recon commands across PATH-search retries

        # Process tree: pid → parent_pid, pid → cmdline
        self._proc_tree: dict[str, str] = {}
        self._proc_args: dict[str, str] = {}

        # ── Cluster event buckets ──────────────────────────────────────
        self.network_events:    list[dict] = []
        self.dns_events:        list[dict] = []
        self.dropper_events:    list[dict] = []
        self.persistence_events: list[dict] = []
        self.exfil_events:      list[dict] = []
        self.reverse_shell_events: list[dict] = []

        # ── Boolean indicators ─────────────────────────────────────────
        self.anon_exec_mmap         = False
        self.memfd_create_exec      = False
        self.privilege_escalation   = False
        self.stdio_redirect_to_socket = False
        self.obfuscated_cmdline     = False
        self.hidden_file_created    = False
        self.shell_spawned_by_installer = False
        self.dropper_chain_detected = False
        self.raw_socket_created     = False

    # ── Public API ────────────────────────────────────────────────────

    def observe_line(self, line: str) -> None:
        stripped = line.strip()
        if not stripped:
            return
        self.raw_lines.append(stripped)

        match = self._PREFIX_RE.match(stripped)
        if match:
            kind, tag, content = match.groups()
            if kind == "MARKER":
                parts = tag.split(":")
                if parts:
                    self.current_phase = parts[0]
            elif kind == "PHASE":
                self.current_phase = tag
                self._observe_strace(content, tag, raw_line=stripped)
            elif kind == "STDOUT":
                self._observe_stdout(content, tag)
            return

        # Unprefixed fallback
        self._observe_strace(stripped, self.current_phase, raw_line=stripped)

    def observe_event(self, event: dict[str, Any]) -> None:
        pass  # kept for API compatibility

    # ── Internal: strace line parser ─────────────────────────────────

    def _observe_strace(self, line: str, phase: str, raw_line: str = "") -> None:
        # Text-only heuristics (no regex needed)
        if "xmrig" in line or "minerd" in line or "cpuminer" in line:
            self._add_ioc("crypto", "crypto_miner", 0, phase, {}, raw_line)
            self.crypto_iocs.append("crypto_miner")

        m = self._STRACE_RE.match(line)
        if not m:
            return

        pid      = m.group("pid") or "0"
        syscall  = m.group("syscall")
        args_str = m.group("args")
        ret      = m.group("ret").strip()

        self._dispatch(pid, syscall, args_str, ret, phase, raw_line)

    def _dispatch(
        self, pid: str, syscall: str, args_str: str,
        ret: str, phase: str, raw_line: str,
    ) -> None:

        # ── Process tree maintenance ───────────────────────────────────
        if syscall in ("clone", "fork", "vfork"):
            ret_val = ret.split()[0] if ret else ""
            if ret_val.lstrip("-").isdigit() and int(ret_val) > 0:
                self._proc_tree[ret_val] = pid

        if syscall in ("execve", "execveat"):
            self._proc_args[pid] = args_str
            self._check_execve(pid, args_str, phase, raw_line)

        # ── Network ───────────────────────────────────────────────────
        elif syscall == "connect":
            self._check_connect(pid, args_str, phase, raw_line)

        elif syscall == "socket":
            if "SOCK_RAW" in args_str:
                self._check_raw_socket(args_str, phase, raw_line)

        elif syscall == "sendto" and "sin_port=htons(53)" in args_str:
            self._check_dns_send(pid, args_str, phase, raw_line)

        # ── Stdio redirect (reverse shell) ────────────────────────────
        elif syscall in ("dup2", "dup3"):
            if ("<TCP" in args_str or "<UDP" in args_str):
                if any(f",{fd}" in args_str or f", {fd}" in args_str
                       for fd in ("0", "1", "2")):
                    self.stdio_redirect_to_socket = True
                    self.reverse_shell_events.append({"type": "dup2_socket", "phase": phase})
                    self._add_ioc("process", "stdio_to_socket", 90, phase, {}, raw_line)
                    self.process_iocs.append("stdio_redirected_to_socket")

        # ── File open / write / read ───────────────────────────────────
        elif syscall in ("open", "openat", "creat"):
            self._check_open(pid, syscall, args_str, phase, raw_line)

        # ── chmod / fchmod ────────────────────────────────────────────
        elif syscall in ("chmod", "fchmod", "fchmodat"):
            self._check_chmod(pid, syscall, args_str, phase, raw_line)

        # ── Memory mapping ────────────────────────────────────────────
        elif syscall == "mmap":
            if "PROT_EXEC" in args_str and "PROT_WRITE" in args_str \
                    and "MAP_ANONYMOUS" in args_str:
                self.anon_exec_mmap = True
                self._add_ioc("memory", "anon_exec_mmap", 80, phase, {}, raw_line)
                self.process_iocs.append("anon_exec_mmap")

        # ── memfd_create ──────────────────────────────────────────────
        elif syscall == "memfd_create":
            ret_fd = ret.split()[0] if ret else ""
            if ret_fd.isdigit():
                self.memfd_created.add(ret_fd)

        # ── Privilege escalation ──────────────────────────────────────
        elif syscall in ("setuid", "setresuid", "setgid", "setresgid", "capset"):
            # Only flag during install; exec probes legitimately setuid sometimes
            if phase == "install":
                self.privilege_escalation = True
                self._add_ioc("process", f"privilege_escalation:{syscall}",
                              self._w(60, phase), phase, {"syscall": syscall}, raw_line)
                self.process_iocs.append(f"privilege_escalation:{syscall}")

        # ── ptrace (anti-debug / injection) ───────────────────────────
        elif syscall == "ptrace":
            if "PTRACE_TRACEME" not in args_str:
                self._add_ioc("process", "ptrace_other",
                              self._w(35, phase), phase, {}, raw_line)
                self.process_iocs.append("ptrace_other_process")

    # ── execve analysis ───────────────────────────────────────────────

    def _check_execve(
        self, pid: str, args_str: str, phase: str, raw_line: str,
    ) -> None:
        # Extract first argument (path)
        path = args_str.split(",")[0].strip().strip('"')

        # Obfuscated command
        if "base64" in args_str and ("-d" in args_str or "--decode" in args_str):
            self.obfuscated_cmdline = True
            self._add_ioc("process", "obfuscated_cmdline", 30, phase,
                          {"path": path}, raw_line)
            self.process_iocs.append("obfuscated_cmdline")

        # Shell download chain (curl/wget piped to sh/bash)
        if any(dl in args_str for dl in ("curl ", "wget ")):
            if any(sh in args_str for sh in ("bash", " sh ", "/sh ")):
                if phase == "install":
                    self.shell_spawned_by_installer = True
                    self._add_ioc("process", "shell_download_exec",
                                  self._w(75, phase), phase, {"path": path}, raw_line)
                    self.process_iocs.append("shell_download_exec")

        # Skip legitimate pip temp executions and our own analysis infrastructure
        if _PIP_TMP_RE.match(path):
            return
        if any(path.startswith(p) for p in _ANALYSIS_TMP_PREFIXES):
            return

        # System recon during install — dedup across PATH-search retries
        if phase == "install":
            cmd_name = path.rsplit("/", 1)[-1]
            if cmd_name in _RECON_COMMANDS and cmd_name not in self.recon_seen:
                self.recon_seen.add(cmd_name)
                self._add_ioc("process", "system_recon",
                              self._w(20, phase), phase,
                              {"cmd": cmd_name}, raw_line)
                self.process_iocs.append(f"system_recon:{cmd_name}")

        # Exec from /tmp (but not pip's own temp)
        if path.startswith("/tmp/"):
            ev = {"type": "exec_from_tmp", "path": path}
            self.dropper_events.append(ev)
            self._add_ioc("process", "exec_from_tmp",
                          self._w(45, phase), phase, ev, raw_line)
            self.process_iocs.append(f"exec_from_tmp:{path}")

        # Exec from a file we previously wrote
        if path in self.written_files:
            ev = {"type": "exec_recently_written", "path": path}
            self.dropper_events.append(ev)
            self._add_ioc("process", "exec_recently_written",
                          self._w(45, phase), phase, ev, raw_line)
            self.process_iocs.append(f"exec_recently_written:{path}")

        # Exec from memfd (fileless malware)
        if path in self.memfd_created or any(path in fd for fd in self.memfd_created):
            self.memfd_create_exec = True
            self._add_ioc("process", "memfd_exec", 80, phase, {"path": path}, raw_line)
            self.process_iocs.append(f"memfd_create_exec:{path}")

        # Dropper chain detection via process tree
        if self._is_dropper_chain(pid):
            if not self.dropper_chain_detected:
                self.dropper_chain_detected = True
                self._add_ioc("process", "dropper_chain",
                              self._w(75, phase), phase, {"pid": pid}, raw_line)
                self.process_iocs.append("dropper_chain")

    # ── connect analysis ──────────────────────────────────────────────

    def _check_connect(
        self, pid: str, args_str: str, phase: str, raw_line: str,
    ) -> None:
        if "AF_INET" not in args_str:
            return
        ip_m = _IP_RE.search(args_str)
        if not ip_m:
            return
        ip = ip_m.group(1)

        port_m = _PORT_RE.search(args_str)
        port = int(port_m.group(1)) if port_m else 0

        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return

        if addr.is_private or addr.is_loopback:
            return

        # DNS resolver connect() to port 53 is normal and not suspicious alone.
        if port == 53:
            return

        # Suspicious port — high score regardless of CDN
        if port in _SUSPICIOUS_PORTS:
            self.network_iocs.append(f"suspicious_port:{port}:{ip}")
            self.network_events.append({
                "phase": phase, "action": "connect",
                "external_ip": True, "ip": ip, "port": port,
                "suspicious_port": True,
            })
            self._add_ioc("network", "suspicious_port",
                          self._w(85, phase), phase,
                          {"ip": ip, "port": port}, raw_line)
            return

        # Known CDN — not suspicious
        if self._is_safe_ip(addr):
            return

        # Unknown external IP
        self.network_iocs.append(f"external_ip:{ip}")
        self.network_events.append({
            "phase": phase, "action": "connect",
            "external_ip": True, "ip": ip, "port": port,
        })
        self._add_ioc("network", "external_ip",
                      self._w(25, phase), phase,
                      {"ip": ip, "port": port}, raw_line)

    # ── raw socket analysis ───────────────────────────────────────────

    def _check_raw_socket(self, args_str: str, phase: str, raw_line: str) -> None:
        # AF_NETLINK + safe protocol: used by libc for routing/interface queries — benign
        if "AF_NETLINK" in args_str:
            if any(proto in args_str for proto in _SAFE_NETLINK_PROTOS):
                return
            # Other netlink protocols: low informational score
            self._add_ioc("network", "netlink_raw", self._w(5, phase), phase, {}, raw_line)
            self.network_iocs.append("netlink_raw")
            return

        # AF_PACKET: raw Ethernet frame access (sniffing / injection)
        if "AF_PACKET" in args_str:
            self.raw_socket_created = True
            self._add_ioc("network", "raw_socket_packet", self._w(60, phase), phase, {}, raw_line)
            self.network_iocs.append("raw_socket_packet")
            return

        # AF_INET / AF_INET6: raw IP packet crafting
        if "AF_INET" in args_str:
            self.raw_socket_created = True
            self._add_ioc("network", "raw_socket", self._w(40, phase), phase, {}, raw_line)
            self.network_iocs.append("raw_socket")
            return

        # Unknown family with SOCK_RAW — unusual but not definitely malicious
        self._add_ioc("network", "raw_socket", self._w(20, phase), phase, {}, raw_line)
        self.network_iocs.append("raw_socket")

    # ── DNS send analysis ─────────────────────────────────────────────

    def _check_dns_send(
        self, pid: str, args_str: str, phase: str, raw_line: str,
    ) -> None:
        # DNS queries for package registry infrastructure are normal during install
        if any(label in args_str for label in _SAFE_REGISTRY_DNS):
            return

        self.dns_events.append({"phase": phase})
        self.dns_iocs.append("dns_query")

        # Check for dynamic DNS domains in the raw args
        for domain in _DDNS_DOMAINS:
            if domain in args_str:
                self._add_ioc("dns", "ddns_query",
                              self._w(50, phase), phase,
                              {"domain": domain}, raw_line)
                self.dns_iocs.append(f"ddns:{domain}")
                return

        self._add_ioc("dns", "dns_query_install",
                      self._w(10, phase), phase, {}, raw_line)

    # ── file open analysis ────────────────────────────────────────────

    def _check_open(
        self, pid: str, syscall: str, args_str: str, phase: str, raw_line: str,
    ) -> None:
        parts = args_str.split(",")
        if syscall == "openat":
            path = parts[1].strip().strip('"') if len(parts) >= 2 else ""
        else:
            path = parts[0].strip().strip('"')

        is_write = any(f in args_str for f in ("O_WRONLY", "O_RDWR", "O_CREAT"))
        is_read  = "O_RDONLY" in args_str and not is_write

        if is_write:
            self.written_files.add(path)

            if any(p in path for p in _PERSIST_PATHS):
                ev = {"path": path}
                self.persistence_events.append(ev)
                self._add_ioc("file", "persistence_write", 60, phase, ev, raw_line)
                self.file_iocs.append(f"persistence_path:{path}")

            # Hidden file
            if (path.startswith(".") or "/." in path) and "config" not in path:
                self.hidden_file_created = True

        if is_read:
            if any(p in path for p in _SENSITIVE_READ_PATHS):
                ev = {"path": path}
                self.exfil_events.append(ev)
                self._add_ioc("file", "sensitive_file_read",
                              self._w(30, phase), phase, ev, raw_line)
                self.file_iocs.append(f"sensitive_file:{path}")

    # ── chmod analysis ────────────────────────────────────────────────

    def _check_chmod(
        self, pid: str, syscall: str, args_str: str, phase: str, raw_line: str,
    ) -> None:
        EXEC_MODES = ("0755", "0777", "0711", "0111", "S_IXUSR", "0775")
        if not any(m in args_str for m in EXEC_MODES):
            return
        parts = args_str.split(",")
        path = parts[1].strip().strip('"') if syscall == "fchmodat" and len(parts) >= 2 \
            else parts[0].strip().strip('"')
        if path in self.written_files:
            ev = {"type": "chmod_exec_downloaded", "path": path}
            self.dropper_events.append(ev)
            self._add_ioc("process", "chmod_exec_downloaded",
                          self._w(20, phase), phase, ev, raw_line)
            self.process_iocs.append(f"chmod_exec_downloaded:{path}")

    # ── stdout analysis (from pip / process output) ───────────────────

    def _observe_stdout(self, line: str, phase: str) -> None:
        if "/dev/tcp" in line or "bash -i" in line or ">& /dev/tcp" in line:
            self.reverse_shell_events.append({"type": "stdout_reverse_shell", "phase": phase})
            self._add_ioc("process", "reverse_shell_stdout", 90, phase, {}, line)
            self.process_iocs.append("reverse_shell")

        # Anti-analysis / sandbox-evasion messages printed by the package
        low = line.lower()
        for phrase in _ANTI_ANALYSIS_PHRASES:
            if phrase in low:
                self._add_ioc("process", "anti_analysis_stdout",
                              self._w(70, phase), phase, {"phrase": phrase}, line)
                self.process_iocs.append("anti_analysis_output")
                break

        # File creation/write confirmed in stdout (e.g. malicious setup.py hooks)
        m = _STDOUT_FILE_WRITE_RE.search(line)
        if m:
            path = m.group(1).rstrip("',\"")
            top = path.lstrip("/").split("/")[0]
            is_suspicious_root = top and top not in _SAFE_ROOT_DIRS
            is_persist = any(p in path for p in _PERSIST_PATHS)
            is_sensitive = any(p in path for p in _SENSITIVE_READ_PATHS)
            if is_suspicious_root or is_persist or is_sensitive:
                self._add_ioc("file", "stdout_sensitive_write",
                              self._w(55, phase), phase, {"path": path}, line)
                self.file_iocs.append(f"sensitive_file:{path}")

    # ── Build final evidence ──────────────────────────────────────────

    def build_evidence(self) -> IOCEvidence:
        # Collect scored IOC events and total score
        total_score = 0
        for ev in self.ioc_events:
            total_score += ev.score_contribution

        # Cluster-level additions (for patterns not captured per-line)
        exfil_cluster = len(self.exfil_events) > 0 and len(self.network_events) > 0
        if exfil_cluster:
            total_score += 65

        reverse_shell = len(self.reverse_shell_events) > 0 or self.stdio_redirect_to_socket
        if reverse_shell and not any(e.subcategory in ("stdio_to_socket", "reverse_shell_stdout")
                                     for e in self.ioc_events):
            total_score += 90

        if self.hidden_file_created:
            total_score += 15

        if self.shell_spawned_by_installer and not any(
            e.subcategory == "shell_download_exec" for e in self.ioc_events
        ):
            total_score += 25

        total_score = min(total_score, 100)
        dynamic_hit = total_score > 0

        if total_score >= 70:
            verdict = "malicious"
        elif total_score >= 25:
            verdict = "suspicious"
        else:
            verdict = "benign"

        hard_file_iocs = [f for f in self.file_iocs if not f.startswith("uploaded_artifact:")]
        suspicious_syscalls = len(self.process_iocs) + len(hard_file_iocs) + len(self.dns_iocs)
        sensitive_writes = len(self.persistence_events)
        outbound = sum(1 for n in self.network_iocs if n.startswith("external_ip:"))

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
            ioc_events=list(self.ioc_events),
            risk_score=total_score,
        )

    # ── Helpers ───────────────────────────────────────────────────────

    def _w(self, base: int, phase: str) -> int:
        """Apply phase multiplier to a base score."""
        return int(base * _PHASE_MULT.get(phase, 1.0))

    def _add_ioc(
        self, category: str, subcategory: str, score: int,
        phase: str, detail: dict, raw_line: str,
    ) -> None:
        self.ioc_events.append(IOCEvent(
            phase=phase,
            category=category,
            subcategory=subcategory,
            score_contribution=score,
            detail=detail,
            raw_line=raw_line,
        ))

    @staticmethod
    def _is_safe_ip(addr: ipaddress.IPv4Address) -> bool:
        return any(addr in net for net in _SAFE_NETS)

    def _is_dropper_chain(self, pid: str) -> bool:
        """Walk the process ancestor chain looking for installer→shell→downloader."""
        chain_args: list[str] = []
        cur = pid
        for _ in range(8):
            cmd = self._proc_args.get(cur, "")
            if cmd:
                chain_args.append(cmd)
            parent = self._proc_tree.get(cur)
            if not parent:
                break
            cur = parent
        chain_str = " | ".join(chain_args)
        return bool(
            re.search(r"\b(bash|sh|dash|zsh)\b", chain_str)
            and re.search(r"\b(curl|wget|python|nc|ncat|netcat)\b", chain_str)
        )
