"""Unit tests for input validators."""

from __future__ import annotations

import pytest

from anonymizer.core.exceptions import ValidationError
from anonymizer.utils.validators import (
    ensure_valid_pcap,
    has_valid_extension,
    is_valid_ip,
    is_valid_ipv4,
    is_valid_ipv6,
    is_valid_mac,
    is_valid_port,
)


@pytest.mark.parametrize(
    "addr,expected",
    [
        ("0.0.0.0", True),
        ("127.0.0.1", True),
        ("192.168.1.1", True),
        ("255.255.255.255", True),
        ("256.0.0.0", False),
        ("1.2.3", False),
        ("hello", False),
        ("", False),
        ("::1", False),  # IPv6, not IPv4
    ],
)
def test_is_valid_ipv4(addr: str, expected: bool) -> None:
    assert is_valid_ipv4(addr) is expected


@pytest.mark.parametrize(
    "addr,expected",
    [
        ("::", True),
        ("::1", True),
        ("fe80::1", True),
        ("2001:db8::1", True),
        ("ff02::1", True),
        ("127.0.0.1", False),  # IPv4, not IPv6
        ("gggg::1", False),
        ("", False),
    ],
)
def test_is_valid_ipv6(addr: str, expected: bool) -> None:
    assert is_valid_ipv6(addr) is expected


def test_is_valid_ip_accepts_both_families() -> None:
    assert is_valid_ip("127.0.0.1")
    assert is_valid_ip("::1")
    assert not is_valid_ip("not-an-address")


@pytest.mark.parametrize(
    "mac,expected",
    [
        ("00:11:22:33:44:55", True),
        ("aa:bb:cc:dd:ee:ff", True),
        ("AA:BB:CC:DD:EE:FF", True),
        ("00-11-22-33-44-55", False),  # we want colon-separated
        ("00:11:22:33:44", False),
        ("zz:11:22:33:44:55", False),
        ("", False),
    ],
)
def test_is_valid_mac(mac: str, expected: bool) -> None:
    assert is_valid_mac(mac) is expected


@pytest.mark.parametrize(
    "port,expected",
    [
        (0, True),
        (1, True),
        (80, True),
        (65535, True),
        (-1, False),
        (65536, False),
        ("80", False),  # type-strict: must be int
        (None, False),
    ],
)
def test_is_valid_port(port: object, expected: bool) -> None:
    assert is_valid_port(port) is expected


@pytest.mark.parametrize(
    "name,expected",
    [
        ("foo.pcap", True),
        ("foo.pcapng", True),
        ("foo.PCAP", True),
        ("foo.PCAPNG", True),
        ("foo.txt", False),
        ("foo", False),
    ],
)
def test_has_valid_extension(name: str, expected: bool) -> None:
    assert has_valid_extension(name) is expected


def test_ensure_valid_pcap_missing(tmp_path: object) -> None:
    with pytest.raises(ValidationError):
        ensure_valid_pcap(str(tmp_path / "does-not-exist.pcapng"))  # type: ignore[operator]


def test_ensure_valid_pcap_bad_extension(tmp_path) -> None:  # type: ignore[no-untyped-def]
    p = tmp_path / "foo.txt"
    p.write_bytes(b"not a pcap")
    with pytest.raises(ValidationError):
        ensure_valid_pcap(str(p))


def test_ensure_valid_pcap_happy_path(tmp_path) -> None:  # type: ignore[no-untyped-def]
    # Build a minimal valid pcap (libpcap classic format, link type EN10MB,
    # one tiny synthetic packet) without depending on a sample file.
    import struct

    p = tmp_path / "foo.pcap"
    global_header = struct.pack(
        "<IHHIIII",
        0xA1B2C3D4,  # magic
        2, 4,        # version major/minor
        0, 0,        # thiszone, sigfigs
        65535,       # snaplen
        1,           # linktype = Ethernet
    )
    payload = b"\x00" * 14  # one empty Ethernet header
    pkt_header = struct.pack("<IIII", 0, 0, len(payload), len(payload))
    p.write_bytes(global_header + pkt_header + payload)
    ensure_valid_pcap(str(p))  # should not raise


def test_ensure_valid_pcap_corrupted(tmp_path) -> None:  # type: ignore[no-untyped-def]
    p = tmp_path / "foo.pcapng"
    p.write_bytes(b"not actually pcap content")
    with pytest.raises(ValidationError):
        ensure_valid_pcap(str(p))
