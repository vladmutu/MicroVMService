"""Host-side IOC detector for the microVM agent stream.

The detector accepts both raw strace/log lines and the structured JSON events
emitted by real_agent.py. It keeps the legacy raw-line behavior for tests, but
the primary path is event-aware scoring so the host can reason about phase,
ancestry, and derived artifact kinds.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from typing import Any


@dataclass(slots=True)
class IOCEvidence:
    verdict: str
    dynamic_hit: bool
    network_iocs: list[str]
    process_iocs: list[str]
    file_iocs: list[str]
    dns_iocs: list[str]
    crypto_iocs: list[str]
    raw_line_count: int
    outbound_connections: int = 0
    suspicious_syscalls: int = 0
    sensitive_writes: int = 0


class DynamicIOCDetector:
    _SUSPICIOUS_PORTS = {4444, 5555, 6667, 9001, 9050, 31337}
    _LOOPBACK_PREFIXES = ("127.", "::1")

    _PUBLIC_IP_RE = re.compile(
        r'(?:sin_addr=inet_addr\("(?P<ip2>\d{1,3}(?:\.\d{1,3}){3})"\)|'
        r'inet_pton\([^)]*,\s*"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"|'
        r'(?:connect|sendto)\([^\n]*?(?<=[^0-9])(?P<ip3>\d{1,3}(?:\.\d{1,3}){3}))'
    )
    _PORT_RE = re.compile(r"htons\((\d+)\)|sin_port=htons\((\d+)\)")
    _QUOTED_PATH_RE = re.compile(r'"([^"\\]*(?:\\.[^"\\]*)*)"')
    _DNS_DOMAIN_RE = re.compile(
        r'getaddrinfo\([^\n]*"(?P<domain>[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
        r'(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*)"',
        re.IGNORECASE,
    )
    _SHELL_RE = re.compile(r"(?:/bin/(?:sh|bash|dash|zsh|ksh)|\\bsh\\b|\\bbash\\b)", re.IGNORECASE)
    _DOWNLOAD_RE = re.compile(r"(?:curl|wget|http|base64|eval|nc\\b|ncat\\b|socat\\b)", re.IGNORECASE)
    _REVERSE_SHELL_RE = re.compile(
        r"(?:bash\s+-i|/dev/tcp/|/dev/udp/|mkfifo|nc\s+-[^\n]*-e\s|ncat\s.*--exec)",
        re.IGNORECASE,
    )
    _CRYPTO_MINER_RE = re.compile(
        r"(?:xmrig|minerd|cpuminer|stratum\+tcp://|stratum\+ssl://|monero|cryptonight|ethash|pool\.minergate)",
        re.IGNORECASE,
    )
    _DATA_STAGING_RE = re.compile(
        r"(?:tar\s+c[^\n]*\|.*(?:curl|wget|nc)|zip\s+-r[^\n]*/tmp/|base64\s+[^\n]*/etc/|cat\s+/etc/passwd|eval\s+\"[^\"]*curl[^\n]*\")",
        re.IGNORECASE,
    )
    _DYNAMIC_CODE_RE = re.compile(
        r"(?:eval\s*\(|new\s+Function\s*\(|Function\s*\(|vm\.runIn(?:Context|ThisContext)\s*\()",
        re.IGNORECASE,
    )
    _ENV_ACCESS_RE = re.compile(
        r"process\.env\.(?:AWS_|GITHUB_|NPM_|AUTH|TOKEN|SECRET|PASSWORD|KEY|HOME)",
        re.IGNORECASE,
    )
    _INSTALL_HOOK_RE = re.compile(r"(?:preinstall|postinstall|install|prepare)(?:\s*:|\.js|\.sh)", re.IGNORECASE)
    _SUSPICIOUS_REQUIRE_RE = re.compile(
        r"require\s*\(\s*[\"\'](?:child_process|spawn|exec|fork|cluster|net|http|https|dgram|tls|fs|crypto)[\"\']",
        re.IGNORECASE,
    )
    _PERSISTENCE_RE = re.compile(
        r"(?:/etc/cron[^\s\"]*|/etc/rc\.local|/etc/rc[^\s\"]*|\.bashrc|\.bash_profile|\.profile|\.ssh/authorized_keys)$",
        re.IGNORECASE,
    )
    _SECRET_PATH_RE = re.compile(
        r"(?:/\.ssh/|/\.aws/|/\.gnupg/|/etc/passwd|/etc/shadow|/proc/[^\s\"]+/(?:environ|cmdline))",
        re.IGNORECASE,
    )
    _TMP_PATH_RE = re.compile(r"(?:^/tmp/|^/var/tmp/|^/dev/shm/)", re.IGNORECASE)

    def __init__(self) -> None:
        self.network_iocs: list[str] = []
        self.process_iocs: list[str] = []
        self.file_iocs: list[str] = []
        self.dns_iocs: list[str] = []
        self.crypto_iocs: list[str] = []
        self.raw_lines: list[str] = []
        self._external_network_seen = False
        self._install_network_seen = False
        self._monitor_network_seen = False
        self._install_dns_seen = False
        self._reverse_shell_seen = False
        self._anon_exec_mmap_seen = False
        self._memfd_create_ts_by_pid: dict[int, float] = {}
        self._memfd_exec_seen = False
        self._privilege_escalation_seen = False
        self._persistence_seen = False
        self._exfil_seen = False
        self._obfuscated_cmdline_seen = False
        self._shell_spawned_by_installer_seen = False
        self._hidden_file_created_seen = False
        self._dropper_seen = False
        self._crypto_seen = False
        self._secret_access_seen = False

    def observe_line(self, line: str) -> None:
        """Accept a raw log/strace line or an embedded JSON event."""
        self.raw_lines.append(line)
        stripped = line.strip()
        if not stripped:
            return

        if stripped.startswith("{"):
            with self._silence_json_error():
                event = json.loads(stripped)
            if isinstance(event, dict) and event.get("event"):
                self.observe_event(event)
                return

        self._observe_text_line(stripped)

    def observe_event(self, event: dict[str, Any]) -> None:
        event_type = event.get("event")
        phase = self._phase(event)
        pid = self._int(event.get("pid"))
        ppid = self._int(event.get("ppid"))
        ts = self._float(event.get("ts"))

        if event_type == "syscall_event":
            raw = event.get("raw")
            if isinstance(raw, str) and raw:
                self._observe_text_line(raw)
            syscall = str(event.get("syscall") or "")
            args = self._list_of_str(event.get("args"))
            args_raw = str(event.get("args_raw") or "")
            return_value = str(event.get("return_value") or "")

            if syscall in {"execve", "execveat"}:
                self._observe_exec_event(
                    phase=phase,
                    pid=pid,
                    ppid=ppid,
                    args=args,
                    args_raw=args_raw,
                    return_value=return_value,
                    ts=ts,
                )
            elif syscall in {"connect", "sendto", "recvfrom", "sendmsg", "recvmsg", "sendmmsg", "recvmmsg", "socket", "bind", "listen", "shutdown", "getsockopt", "setsockopt"}:
                self._observe_network_event(event)
            elif syscall in {"open", "openat", "creat", "read", "write", "pread64", "pwrite64", "readv", "writev", "unlink", "unlinkat", "rename", "renameat", "renameat2", "chmod", "fchmod", "fchmodat", "chown", "fchown", "fchownat", "link", "linkat", "symlink", "symlinkat", "readlink", "readlinkat", "mkdir", "mkdirat", "rmdir", "truncate", "ftruncate", "stat", "fstat", "lstat", "statx", "newfstatat", "access", "faccessat"}:
                self._observe_file_event(event)
            elif syscall in {"getuid", "geteuid", "getgid", "getegid", "getresuid", "getresgid", "setuid", "seteuid", "setgid", "setegid", "setresuid", "setresgid", "capget", "capset", "prctl"}:
                self._observe_credential_event(event)
            elif syscall in {"ptrace", "pipe", "pipe2", "dup", "dup2", "dup3", "memfd_create", "inotify_init", "inotify_init1", "inotify_add_watch", "timerfd_create", "eventfd", "eventfd2", "fcntl", "ioctl", "syslog"}:
                self._observe_ipc_event(event)
            elif syscall in {"mmap", "mprotect"}:
                self._observe_mmap_event(event)
            return

        if event_type == "process_start":
            self._observe_process_start(event)
            return

        if event_type == "network_event":
            self._observe_network_event(event)
            return

        if event_type == "file_event":
            self._observe_file_event(event)
            return

        if event_type == "dns_event":
            self._observe_dns_event(event)
            return

        if event_type == "artifact_created":
            self._observe_artifact_event(event)
            return

        if event_type == "credential_event":
            self._observe_credential_event(event)
            return

        if event_type == "ipc_event":
            self._observe_ipc_event(event)
            return

        if event_type == "mmap_event":
            self._observe_mmap_event(event)
            return

        if event_type == "stdio_line":
            message = event.get("message")
            if isinstance(message, str) and message:
                self._observe_text_line(message)
            return

    def _observe_text_line(self, line: str) -> None:
        if "connect(" in line or "sendto(" in line:
            self._observe_network_text(line)
        if "execve(" in line:
            self._observe_exec_text(line)
        if "open(" in line or "openat(" in line:
            self._observe_file_text(line)
        if "getaddrinfo(" in line:
            self._observe_dns_text(line)

        self._observe_crypto_text(line)
        self._observe_reverse_shell_text(line)
        self._observe_data_staging_text(line)
        self._observe_dynamic_code_text(line)
        self._observe_env_access_text(line)
        self._observe_install_hooks_text(line)
        self._observe_suspicious_requires_text(line)

    def _observe_network_text(self, line: str) -> None:
        external_ip = None
        for match in self._PUBLIC_IP_RE.finditer(line):
            ip_text = match.group("ip") or match.group("ip2") or match.group("ip3")
            if ip_text and self._is_public_ip(ip_text):
                external_ip = ip_text
                self._append_unique(self.network_iocs, f"public_ip:{ip_text}")
                self._external_network_seen = True
                break
        for match in self._PORT_RE.finditer(line):
            port_text = match.group(1) or match.group(2)
            if not port_text:
                continue
            try:
                port = int(port_text)
            except ValueError:
                continue
            if port in self._SUSPICIOUS_PORTS:
                self._append_unique(self.network_iocs, f"suspicious_port:{port}")
                break
        if external_ip and ("connect(" in line or "sendto(" in line):
            self._append_unique(self.network_iocs, f"external_connect:{external_ip}")

    def _observe_exec_text(self, line: str) -> None:
        if self._REVERSE_SHELL_RE.search(line):
            self._append_unique(self.process_iocs, f"reverse_shell:{line[:200]}")
            self._reverse_shell_seen = True
        if self._SHELL_RE.search(line) and self._DOWNLOAD_RE.search(line):
            self._append_unique(self.process_iocs, f"shell_download_exec:{line[:200]}")
            self._shell_spawned_by_installer_seen = True

    def _observe_file_text(self, line: str) -> None:
        match = self._QUOTED_PATH_RE.search(line)
        if not match:
            return
        path = self._unescape(match.group(1))
        if self._is_sensitive_path(path):
            self._append_unique(self.file_iocs, f"sensitive_file:{path}")
            self._secret_access_seen = True

    def _observe_dns_text(self, line: str) -> None:
        match = self._DNS_DOMAIN_RE.search(line)
        if not match:
            return
        domain = match.group("domain")
        labels = domain.split(".")
        if any(len(label) > 40 for label in labels) or len(labels) > 6:
            self._append_unique(self.dns_iocs, f"dns_exfil_suspect:{domain}")

    def _observe_crypto_text(self, line: str) -> None:
        if self._CRYPTO_MINER_RE.search(line):
            self._append_unique(self.crypto_iocs, f"crypto_miner:{line[:200]}")
            self._crypto_seen = True

    def _observe_reverse_shell_text(self, line: str) -> None:
        if self._REVERSE_SHELL_RE.search(line):
            self._append_unique(self.process_iocs, f"reverse_shell:{line[:200]}")
            self._reverse_shell_seen = True

    def _observe_data_staging_text(self, line: str) -> None:
        if self._DATA_STAGING_RE.search(line):
            self._append_unique(self.process_iocs, f"data_staging:{line[:200]}")

    def _observe_dynamic_code_text(self, line: str) -> None:
        if self._DYNAMIC_CODE_RE.search(line):
            self._append_unique(self.process_iocs, f"dynamic_code_exec:{line[:200]}")

    def _observe_env_access_text(self, line: str) -> None:
        if self._ENV_ACCESS_RE.search(line):
            self._append_unique(self.process_iocs, f"env_var_access:{line[:200]}")

    def _observe_install_hooks_text(self, line: str) -> None:
        if self._INSTALL_HOOK_RE.search(line):
            self._append_unique(self.process_iocs, f"install_hook:{line[:200]}")

    def _observe_suspicious_requires_text(self, line: str) -> None:
        if self._SUSPICIOUS_REQUIRE_RE.search(line):
            self._append_unique(self.process_iocs, f"suspicious_require:{line[:200]}")

    def _observe_process_start(self, event: dict[str, Any]) -> None:
        phase = self._phase(event)
        pid = self._int(event.get("pid"))
        ppid = self._int(event.get("ppid"))
        binary = str(event.get("binary") or "")
        args = self._list_of_str(event.get("args"))
        shell_invocation = bool(event.get("shell_invocation")) or self._is_shell_binary(binary)
        inline_command = bool(event.get("inline_command")) or ("-c" in args)
        downloads_and_runs = bool(event.get("downloads_and_runs")) or (shell_invocation and inline_command and self._contains_any(" ".join(args), ("curl", "wget", "http", "base64", "eval")))
        obfuscated_cmdline = bool(event.get("obfuscated_cmdline")) or any(len(arg) > 256 for arg in args)
        exec_from_tmp = bool(event.get("exec_from_tmp")) or self._TMP_PATH_RE.match(binary or "") is not None
        recently_written = bool(event.get("recently_written_file"))
        late_spawn = bool(event.get("late_spawn"))

        if shell_invocation and inline_command and downloads_and_runs:
            self._append_unique(self.process_iocs, f"shell_download_exec:{binary}:{' '.join(args)[:200]}")
            self._shell_spawned_by_installer_seen = True

        if obfuscated_cmdline:
            self._append_unique(self.process_iocs, f"obfuscated_cmdline:{binary}:{' '.join(args)[:200]}")
            self._obfuscated_cmdline_seen = True

        if shell_invocation and phase == "install":
            self._append_unique(self.process_iocs, f"shell_spawned_by_installer:{binary}:{' '.join(args)[:200]}")
            self._shell_spawned_by_installer_seen = True

        if exec_from_tmp or recently_written:
            reason = "exec_from_tmp" if exec_from_tmp else "exec_recently_written"
            self._append_unique(self.process_iocs, f"{reason}:{binary}")
            self._dropper_seen = True

        if late_spawn and phase == "monitor":
            self._append_unique(self.process_iocs, f"late_spawn_monitor:{binary}:{ppid if ppid is not None else 'unknown'}")

        if pid is not None and pid in self._memfd_create_ts_by_pid and phase in {"install", "exec", "monitor"}:
            self._memfd_exec_seen = True

    def _observe_network_event(self, event: dict[str, Any]) -> None:
        phase = self._phase(event)
        pid = self._int(event.get("pid"))
        action = str(event.get("action") or event.get("syscall") or "")
        ip = event.get("ip")
        port = self._int(event.get("port"))
        payload_size = event.get("payload_size")
        failed = bool(event.get("failed"))

        destination = None
        if isinstance(ip, str) and ip:
            destination = f"{ip}:{port}" if port is not None else ip
            if self._is_external_ip(ip):
                self._external_network_seen = True
                if action == "connect":
                    if phase == "install":
                        self._install_network_seen = True
                    if phase == "monitor":
                        self._monitor_network_seen = True
                self._append_unique(self.network_iocs, f"external_ip:{destination}")

        if port in self._SUSPICIOUS_PORTS:
            self._append_unique(self.network_iocs, f"suspicious_port:{port}")

        if action in {"connect", "sendto", "sendmsg", "recvmsg", "sendmmsg", "recvmmsg"} and destination:
            self._append_unique(self.network_iocs, f"network:{phase}:{action}:{destination}")

        if action in {"connect", "sendto", "sendmsg", "recvmsg", "sendmmsg", "recvmmsg"} and port == 53:
            self._append_unique(self.dns_iocs, f"dns_network:{phase}:{destination or 'unknown'}")
            if phase == "install":
                self._install_dns_seen = True

        if pid is not None and self._secret_access_seen and action in {"connect", "sendto", "sendmsg", "recvmsg", "sendmmsg", "recvmmsg"}:
            self._exfil_seen = True

        if action == "connect" and phase == "monitor" and destination:
            self._monitor_network_seen = True

        if failed and payload_size is not None and isinstance(payload_size, int) and payload_size > 0:
            self._append_unique(self.network_iocs, f"failed_network:{action}:{destination or 'unknown'}")

    def _observe_file_event(self, event: dict[str, Any]) -> None:
        phase = self._phase(event)
        path = event.get("path")
        target_path = event.get("target_path")
        access_type = str(event.get("access_type") or "")
        hidden_file = bool(event.get("hidden_file"))
        size = event.get("size")
        operation = str(event.get("operation") or event.get("syscall") or "")

        if isinstance(path, str) and path:
            if self._is_persistence_path(path):
                self._append_unique(self.file_iocs, f"persistence_path:{path}")
                self._persistence_seen = True
            if self._is_sensitive_path(path):
                self._append_unique(self.file_iocs, f"sensitive_file:{path}")
                self._secret_access_seen = True
            if hidden_file and access_type == "create":
                self._append_unique(self.file_iocs, f"hidden_file_created:{path}")
                self._hidden_file_created_seen = True

        if operation in {"write", "pwrite64", "writev"} and isinstance(path, str) and path:
            self._append_unique(self.file_iocs, f"write:{path}")

        if operation in {"unlink", "unlinkat"} and isinstance(path, str) and path:
            self._append_unique(self.file_iocs, f"delete:{path}")

        if operation in {"chmod", "fchmod", "fchmodat"} and isinstance(path, str) and path:
            if self._TMP_PATH_RE.match(path) or self._is_persistence_path(path):
                self._append_unique(self.file_iocs, f"chmod:{path}")

        if phase in {"install", "exec", "monitor"} and hidden_file and access_type == "create":
            self._hidden_file_created_seen = True

        if isinstance(size, int) and size > 0 and operation in {"write", "pwrite64", "writev"}:
            if isinstance(path, str) and path in self.raw_lines:
                self._dropper_seen = True

        if isinstance(path, str) and path and self._TMP_PATH_RE.match(path) and access_type == "create":
            self._dropper_seen = True

        if isinstance(path, str) and self._secret_access_seen and access_type in {"read", "write", "create", "stat"}:
            self._exfil_seen = True

        if isinstance(target_path, str) and target_path and self._is_persistence_path(target_path):
            self._persistence_seen = True

    def _observe_dns_event(self, event: dict[str, Any]) -> None:
        phase = self._phase(event)
        syscall = str(event.get("syscall") or "")
        ip = event.get("ip")
        port = self._int(event.get("port"))
        if port == 53 or syscall:
            label = f"dns_event:{phase}:{syscall}:{ip or 'unknown'}:{port or 'unknown'}"
            self._append_unique(self.dns_iocs, label)
            if phase == "install":
                self._install_dns_seen = True

    def _observe_artifact_event(self, event: dict[str, Any]) -> None:
        kind = str(event.get("kind") or "")
        path = event.get("path")
        pid = self._int(event.get("pid"))
        age_seconds = event.get("age_seconds")

        if kind == "exec_from_tmp":
            self._append_unique(self.process_iocs, f"exec_from_tmp:{path}")
            self._dropper_seen = True
        elif kind == "exec_recently_written":
            self._append_unique(self.process_iocs, f"exec_recently_written:{path}")
            self._dropper_seen = True
        elif kind == "write_delete_quick":
            self._append_unique(self.process_iocs, f"write_delete_quick:{path}")
            self._dropper_seen = True
        elif kind == "anon_exec_mmap":
            self._append_unique(self.process_iocs, "anon_exec_mmap")
            self._anon_exec_mmap_seen = True
        elif kind == "mprotect_exec":
            self._append_unique(self.process_iocs, f"mprotect_exec:{event.get('prot')}")
        elif kind == "stdio_redirected_to_socket":
            self._append_unique(self.process_iocs, "stdio_redirected_to_socket")
            self._reverse_shell_seen = True
        elif kind == "memfd_create":
            self._append_unique(self.process_iocs, f"memfd_create:{event.get('name') or ''}")
            if pid is not None:
                self._memfd_create_ts_by_pid[pid] = self._float(event.get("ts"))
        elif kind == "file_made_executable":
            self._append_unique(self.process_iocs, f"file_made_executable:{path}")
            if isinstance(path, str) and self._TMP_PATH_RE.match(path):
                self._dropper_seen = True
        elif kind == "uploaded_artifact":
            self._append_unique(self.file_iocs, f"uploaded_artifact:{path}")

    def _observe_credential_event(self, event: dict[str, Any]) -> None:
        action = str(event.get("action") or "")
        syscall = str(event.get("syscall") or event.get("option") or "")
        if action == "set" or syscall in {"setuid", "seteuid", "setgid", "setegid", "setresuid", "setresgid", "capset"}:
            self._append_unique(self.process_iocs, f"privilege_escalation:{syscall or action}")
            self._privilege_escalation_seen = True

    def _observe_ipc_event(self, event: dict[str, Any]) -> None:
        action = str(event.get("action") or event.get("syscall") or "")
        request = event.get("request")
        old_fd = self._int(event.get("old_fd"))
        new_fd = self._int(event.get("new_fd"))
        pid = self._int(event.get("pid"))
        if action == "ptrace" and str(request or "") != "PTRACE_TRACEME":
            self._append_unique(self.process_iocs, f"ptrace:{request}")
        if action in {"dup", "dup2", "dup3"} and old_fd is not None and new_fd is not None and new_fd <= 2:
            self._append_unique(self.process_iocs, f"stdio_dup:{old_fd}->{new_fd}")
            self._reverse_shell_seen = True
        if action == "memfd_create" and pid is not None:
            self._memfd_create_ts_by_pid[pid] = self._float(event.get("ts"))

    def _observe_mmap_event(self, event: dict[str, Any]) -> None:
        syscall = str(event.get("syscall") or "")
        executable = bool(event.get("executable"))
        anonymous = bool(event.get("anonymous"))
        prot = str(event.get("prot") or "")
        if syscall == "mmap" and executable and anonymous:
            self._append_unique(self.process_iocs, "anon_exec_mmap")
            self._anon_exec_mmap_seen = True
        if syscall == "mprotect" and executable:
            self._append_unique(self.process_iocs, f"mprotect_exec:{prot}")

    def _observe_exec_event(
        self,
        *,
        phase: str,
        pid: int | None,
        ppid: int | None,
        args: list[str],
        args_raw: str,
        return_value: str,
        ts: float,
    ) -> None:
        binary = self._unescape(args[0]) if args else ""
        shell_invocation = self._is_shell_binary(binary)
        inline_command = "-c" in args or "-c" in args_raw
        command_text = " ".join(args)
        downloads_and_runs = shell_invocation and inline_command and self._contains_any(command_text, ("curl", "wget", "http", "base64", "eval", "nc", "ncat", "socat"))
        obfuscated_cmdline = any(len(arg) > 256 for arg in args) or self._contains_any(command_text, ("base64", "\\x", "\\u00", "eval(", "exec("))
        exec_from_tmp = self._is_tmp_path(binary)
        recently_written = False
        if pid is not None and pid in self._memfd_create_ts_by_pid:
            recently_written = ts - self._memfd_create_ts_by_pid[pid] <= 5.0
            if recently_written:
                self._memfd_exec_seen = True

        if shell_invocation and inline_command and downloads_and_runs:
            self._append_unique(self.process_iocs, f"shell_download_exec:{binary}:{command_text[:200]}")
            self._shell_spawned_by_installer_seen = True

        if shell_invocation and phase == "install":
            self._append_unique(self.process_iocs, f"shell_spawned_by_installer:{binary}:{command_text[:200]}")
            self._shell_spawned_by_installer_seen = True

        if exec_from_tmp:
            self._append_unique(self.process_iocs, f"exec_from_tmp:{binary}")
            self._dropper_seen = True

        if recently_written:
            self._append_unique(self.process_iocs, f"memfd_exec:{binary}")
            self._memfd_exec_seen = True

        if obfuscated_cmdline:
            self._append_unique(self.process_iocs, f"obfuscated_cmdline:{binary}:{command_text[:200]}")
            self._obfuscated_cmdline_seen = True

        if pid is not None and phase == "monitor":
            self._append_unique(self.process_iocs, f"monitor_exec:{binary}")

        if ppid is not None and shell_invocation and self._shell_spawned_by_installer_seen and phase == "install":
            self._append_unique(self.process_iocs, f"installer_shell_child:{ppid}->{pid}")

    def build_evidence(self) -> IOCEvidence:
        has_hard_iocs = bool(self.network_iocs or self.process_iocs or self.file_iocs or self.crypto_iocs)
        near_certain = [
            self._reverse_shell_seen,
            self._anon_exec_mmap_seen,
            self._memfd_exec_seen,
            self._install_network_seen,
            self._privilege_escalation_seen,
        ]
        high_suspicion = [
            self._dropper_seen,
            self._persistence_seen,
            self._exfil_seen,
            self._obfuscated_cmdline_seen,
            self._shell_spawned_by_installer_seen,
            self._install_dns_seen,
            self._hidden_file_created_seen,
            self._monitor_network_seen,
        ]

        risk_score = 0
        if self._reverse_shell_seen:
            risk_score += 90
        if self._anon_exec_mmap_seen:
            risk_score += 80
        if self._memfd_exec_seen:
            risk_score += 80
        if self._install_network_seen:
            risk_score += 70
        if self._privilege_escalation_seen:
            risk_score += 70
        if self._dropper_seen:
            risk_score += 50
        if self._persistence_seen:
            risk_score += 60
        if self._exfil_seen:
            risk_score += 65
        if self._obfuscated_cmdline_seen:
            risk_score += 30
        if self._install_dns_seen:
            risk_score += 20
        if self._hidden_file_created_seen:
            risk_score += 15
        if self._shell_spawned_by_installer_seen:
            risk_score += 25
        if self._monitor_network_seen and not self._install_network_seen:
            risk_score += 35

        if risk_score > 100:
            risk_score = 100

        if has_hard_iocs or any(near_certain) or risk_score >= 70:
            verdict = "malicious"
        elif risk_score >= 30 or any(high_suspicion):
            verdict = "suspicious"
        elif self.dns_iocs:
            verdict = "suspicious"
        else:
            verdict = "benign"

        dynamic_hit = bool(
            self.network_iocs
            or self.process_iocs
            or self.file_iocs
            or self.dns_iocs
            or self.crypto_iocs
        )

        return IOCEvidence(
            verdict=verdict,
            dynamic_hit=dynamic_hit,
            network_iocs=list(self.network_iocs),
            process_iocs=list(self.process_iocs),
            file_iocs=list(self.file_iocs),
            dns_iocs=list(self.dns_iocs),
            crypto_iocs=list(self.crypto_iocs),
            raw_line_count=len(self.raw_lines),
            outbound_connections=self._count_unique_destinations(self.network_iocs),
            suspicious_syscalls=len(self.process_iocs) + len(self.file_iocs) + len(self.dns_iocs),
            sensitive_writes=len([ioc for ioc in self.file_iocs if ioc.startswith("persistence_path:") or ioc.startswith("sensitive_file:")]),
        )

    @staticmethod
    def _count_unique_destinations(items: list[str]) -> int:
        destinations = set()
        for item in items:
            if ":" in item:
                destinations.add(item.split(":", 1)[-1])
        return len(destinations)

    @staticmethod
    def _append_unique(items: list[str], value: str) -> None:
        if value not in items:
            items.append(value)

    @staticmethod
    def _phase(event: dict[str, Any]) -> str:
        phase = event.get("phase")
        return str(phase) if isinstance(phase, str) else ""

    @staticmethod
    def _int(value: Any) -> int | None:
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _float(value: Any) -> float:
        try:
            return float(value)
        except (TypeError, ValueError):
            return 0.0

    @staticmethod
    def _list_of_str(value: Any) -> list[str]:
        if isinstance(value, list):
            return [str(item) for item in value]
        return []

    @staticmethod
    def _unescape(value: str) -> str:
        return value.replace('\\"', '"').replace("\\\\", "\\")

    @staticmethod
    def _contains_any(text: str, keywords: tuple[str, ...]) -> bool:
        lower = text.lower()
        return any(keyword.lower() in lower for keyword in keywords)

    @staticmethod
    def _is_shell_binary(binary: str) -> bool:
        lower = binary.lower()
        return lower.endswith(("/sh", "/bash", "/dash", "/zsh", "/ksh")) or lower in {"sh", "bash", "dash", "zsh", "ksh"}

    @classmethod
    def _is_tmp_path(cls, path: str) -> bool:
        return bool(cls._TMP_PATH_RE.match(path))

    @classmethod
    def _is_persistence_path(cls, path: str) -> bool:
        return bool(cls._PERSISTENCE_RE.search(path))

    @classmethod
    def _is_sensitive_path(cls, path: str) -> bool:
        return bool(cls._SECRET_PATH_RE.search(path))

    @classmethod
    def _is_external_ip(cls, ip_text: str) -> bool:
        if any(ip_text.startswith(prefix) for prefix in cls._LOOPBACK_PREFIXES):
            return False
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

    @staticmethod
    def _silence_json_error():
        try:
            from contextlib import suppress
            return suppress(json.JSONDecodeError)
        except Exception:
            from contextlib import suppress
            return suppress(Exception)
