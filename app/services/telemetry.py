from dataclasses import dataclass


@dataclass(slots=True)
class Telemetry:
    suspicious_syscalls: int = 0
    syscall_categories: list[str] | None = None
    outbound_connections: int = 0
    destinations: list[str] | None = None
    sensitive_writes: int = 0
    write_paths: list[str] | None = None
    vm_evasion_observed: bool = False
    timed_out: bool = False

    def normalized(self) -> "Telemetry":
        return Telemetry(
            suspicious_syscalls=max(0, self.suspicious_syscalls),
            syscall_categories=sorted(set(self.syscall_categories or [])),
            outbound_connections=max(0, self.outbound_connections),
            destinations=sorted(set(self.destinations or [])),
            sensitive_writes=max(0, self.sensitive_writes),
            write_paths=sorted(set(self.write_paths or [])),
            vm_evasion_observed=bool(self.vm_evasion_observed),
            timed_out=bool(self.timed_out),
        )
