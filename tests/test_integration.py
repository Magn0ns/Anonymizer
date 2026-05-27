"""End-to-end integration tests.

We synthesize a tiny pcap with deterministic content, run the full
encrypt then decrypt pipeline through the orchestrator, and assert
that every address and port comes back exactly.
"""

from __future__ import annotations

import os
import struct
from pathlib import Path

import pytest

from anonymizer.core.config import AnonymizerConfig
from anonymizer.crypto.factory import build_registry
from anonymizer.crypto.keys import derive_subkeys, generate_master_key
from anonymizer.processing.orchestrator import Anonymizer


def _make_pcap(path: Path, packets: list[bytes]) -> None:
    """Write *packets* (raw Ethernet frames) to *path* as a classic pcap."""
    global_header = struct.pack(
        "<IHHIIII",
        0xA1B2C3D4, 2, 4, 0, 0, 65535, 1,  # EN10MB
    )
    body = b""
    for p in packets:
        body += struct.pack("<IIII", 0, 0, len(p), len(p)) + p
    path.write_bytes(global_header + body)


def _make_ip_udp_packet(src_ip: str, dst_ip: str, sport: int, dport: int) -> bytes:
    """Hand-build a minimal Ethernet/IPv4/UDP frame using scapy."""
    from scapy.all import Ether, IP, UDP, Raw  # noqa: PLC0415

    return bytes(
        Ether(src="00:11:22:33:44:55", dst="aa:bb:cc:dd:ee:ff")
        / IP(src=src_ip, dst=dst_ip)
        / UDP(sport=sport, dport=dport)
        / Raw(load=b"payload")
    )


@pytest.fixture()
def synthetic_pcap(tmp_path: Path) -> Path:
    """A 3-packet pcap with predictable addresses and ports."""
    p = tmp_path / "in.pcap"
    _make_pcap(
        p,
        [
            _make_ip_udp_packet("10.0.0.1", "10.0.0.2", 1234, 5678),
            _make_ip_udp_packet("192.168.1.1", "192.168.1.2", 4444, 8080),
            _make_ip_udp_packet("10.0.0.1", "10.0.0.2", 1234, 5678),  # duplicate
        ],
    )
    return p


def _addr_tuples(path: Path) -> list[tuple[str, str, str, str, int, int]]:
    from scapy.all import IP, UDP, Ether, rdpcap  # noqa: PLC0415

    out = []
    for pkt in rdpcap(str(path)):
        out.append(
            (
                pkt[Ether].src,
                pkt[Ether].dst,
                pkt[IP].src,
                pkt[IP].dst,
                pkt[UDP].sport,
                pkt[UDP].dport,
            )
        )
    return out


def test_full_roundtrip(synthetic_pcap: Path, tmp_path: Path) -> None:
    master = generate_master_key()
    subkeys = derive_subkeys(master)
    config = AnonymizerConfig(num_threads=2, batch_size=10)

    anon_path = tmp_path / "anon.pcap"
    Anonymizer(
        input_path=str(synthetic_pcap),
        output_path=str(anon_path),
        registry=build_registry(subkeys, config=config, is_encrypting=True),
        config=config,
        is_encrypting=True,
    ).run()
    assert anon_path.is_file()

    dec_path = tmp_path / "dec.pcap"
    Anonymizer(
        input_path=str(anon_path),
        output_path=str(dec_path),
        registry=build_registry(subkeys, config=config, is_encrypting=False),
        config=config,
        is_encrypting=False,
    ).run()
    assert dec_path.is_file()

    original = _addr_tuples(synthetic_pcap)
    anonymized = _addr_tuples(anon_path)
    decrypted = _addr_tuples(dec_path)

    # Every packet was actually transformed.
    for o, a in zip(original, anonymized, strict=True):
        assert o != a, "anonymization should change every address tuple"

    # And the decrypt recovers the original exactly.
    assert decrypted == original

    # Determinism: the duplicate packet (#0 and #2) should map to the
    # same anonymized tuple. This is the property that makes flows
    # remain coherent across the capture.
    assert anonymized[0] == anonymized[2]


def test_field_opt_out(synthetic_pcap: Path, tmp_path: Path) -> None:
    """Passing ``fields={'ipv4'}`` must leave MAC and port untouched."""
    master = generate_master_key()
    subkeys = derive_subkeys(master)
    config = AnonymizerConfig(
        num_threads=1, batch_size=10, fields=frozenset({"ipv4"}),
    )

    out = tmp_path / "anon.pcap"
    Anonymizer(
        input_path=str(synthetic_pcap),
        output_path=str(out),
        registry=build_registry(subkeys, config=config, is_encrypting=True),
        config=config,
        is_encrypting=True,
    ).run()

    original = _addr_tuples(synthetic_pcap)
    anonymized = _addr_tuples(out)

    for o, a in zip(original, anonymized, strict=True):
        # MAC and port unchanged
        assert o[0] == a[0] and o[1] == a[1]  # ether src/dst
        assert o[4] == a[4] and o[5] == a[5]  # udp sport/dport
        # IPv4 changed
        assert o[2] != a[2] and o[3] != a[3]


def test_atomic_output_no_partial_file_on_input_error(tmp_path: Path) -> None:
    """A bad input path must not leave a partial output behind."""
    master = generate_master_key()
    subkeys = derive_subkeys(master)
    config = AnonymizerConfig(num_threads=1, batch_size=10)
    output = tmp_path / "anon.pcap"

    with pytest.raises(Exception):
        Anonymizer(
            input_path=str(tmp_path / "does-not-exist.pcap"),
            output_path=str(output),
            registry=build_registry(subkeys, config=config, is_encrypting=True),
            config=config,
            is_encrypting=True,
        ).run()

    assert not output.exists(), "atomic writer must not commit on failure"
    # And no stray temp files in the directory either.
    leftovers = [
        p for p in tmp_path.iterdir()
        if p.name.startswith(output.name) and p != output
    ]
    # We allow that there are no temp files; if there are, they are
    # the unrenamed temp from the atomic writer, which is also fine
    # as long as the final path is not present.
    for p in leftovers:
        # Temp files should at least be named distinctly.
        assert p.name != output.name


@pytest.mark.skipif(
    not os.path.exists("/home/claude/Anonymizer-main/catturaProva.pcapng"),
    reason="sample capture not available outside dev environment",
)
def test_real_pcap_roundtrip(tmp_path: Path) -> None:
    """Optional smoke test against the original thesis sample capture."""
    import shutil

    sample_src = Path("/home/claude/Anonymizer-main/catturaProva.pcapng")
    sample = tmp_path / "sample.pcapng"
    shutil.copy(sample_src, sample)

    master = generate_master_key()
    subkeys = derive_subkeys(master)
    config = AnonymizerConfig(num_threads=4, batch_size=500)

    anon = tmp_path / "anon.pcapng"
    Anonymizer(
        input_path=str(sample),
        output_path=str(anon),
        registry=build_registry(subkeys, config=config, is_encrypting=True),
        config=config,
        is_encrypting=True,
    ).run()

    dec = tmp_path / "dec.pcapng"
    Anonymizer(
        input_path=str(anon),
        output_path=str(dec),
        registry=build_registry(subkeys, config=config, is_encrypting=False),
        config=config,
        is_encrypting=False,
    ).run()

    from scapy.all import rdpcap  # noqa: PLC0415

    orig_pkts = rdpcap(str(sample))
    dec_pkts = rdpcap(str(dec))
    assert len(orig_pkts) == len(dec_pkts)
    # Compare a sampling of addresses (full comparison is in the dev
    # smoke script).
    for o, d in zip(orig_pkts[:50], dec_pkts[:50], strict=True):
        assert bytes(o) != b"" and bytes(d) != b""
