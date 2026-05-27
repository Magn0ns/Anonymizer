"""Tests for key generation, derivation, persistence and integrity."""

from __future__ import annotations

import os
import stat
import sys

import pytest

from anonymizer.core.exceptions import InvalidKeyError as AnonymizerKeyError
from anonymizer.crypto.keys import (
    decode_key_b64,
    derive_subkeys,
    generate_master_key,
    load_key_from_file,
    save_key,
)


def test_master_key_length() -> None:
    assert len(generate_master_key()) == 16


def test_master_key_is_random() -> None:
    # Vanishingly unlikely to collide unless the RNG is broken.
    assert generate_master_key() != generate_master_key()


def test_derive_subkeys_deterministic() -> None:
    key = generate_master_key()
    a = derive_subkeys(key)
    b = derive_subkeys(key)
    assert a.ipv4 == b.ipv4
    assert a.ipv6 == b.ipv6
    assert a.mac == b.mac
    assert a.port == b.port


def test_derive_subkeys_distinct() -> None:
    """Domain-separated sub-keys must not collide with each other."""
    s = derive_subkeys(generate_master_key())
    keys = {s.ipv4, s.ipv6, s.mac, s.port}
    assert len(keys) == 4


def test_derive_subkeys_all_aes128_sized() -> None:
    s = derive_subkeys(generate_master_key())
    for k in (s.ipv4, s.ipv6, s.mac, s.port):
        assert len(k) == 16


def test_save_and_load_key_roundtrip(tmp_path) -> None:  # type: ignore[no-untyped-def]
    key = generate_master_key()
    path = str(tmp_path / "capture_anon_key.txt")
    save_key(key, path, source_filename="capture.pcap")
    assert load_key_from_file(path) == key


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX-only permission semantics")
def test_save_key_sets_0600(tmp_path) -> None:  # type: ignore[no-untyped-def]
    path = str(tmp_path / "key.txt")
    save_key(generate_master_key(), path, source_filename="x.pcap")
    mode = stat.S_IMODE(os.stat(path).st_mode)
    assert mode == 0o600, f"expected 0600, got {oct(mode)}"


def test_load_key_rejects_tampered_file(tmp_path) -> None:  # type: ignore[no-untyped-def]
    path = str(tmp_path / "key.txt")
    save_key(generate_master_key(), path, source_filename="x.pcap")

    # Tamper with the base64 line (last non-comment line).
    with open(path, encoding="utf-8") as f:
        lines = f.readlines()
    # Flip a character in the base64 payload.
    payload_idx = next(i for i, line in enumerate(lines) if not line.startswith("#"))
    payload = lines[payload_idx].strip()
    flipped = ("A" if payload[0] != "A" else "B") + payload[1:]
    lines[payload_idx] = flipped + "\n"
    with open(path, "w", encoding="utf-8") as f:
        f.writelines(lines)

    with pytest.raises(AnonymizerKeyError):
        load_key_from_file(path)


def test_load_key_rejects_missing_file(tmp_path) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(AnonymizerKeyError):
        load_key_from_file(str(tmp_path / "does-not-exist.txt"))


def test_decode_key_b64_happy_path() -> None:
    import base64
    key = generate_master_key()
    b64 = base64.b64encode(key).decode("ascii")
    assert decode_key_b64(b64, source="--key") == key


def test_decode_key_b64_wrong_length() -> None:
    import base64
    bad = base64.b64encode(b"\x00" * 8).decode("ascii")  # not 16 bytes
    with pytest.raises(AnonymizerKeyError):
        decode_key_b64(bad, source="--key")


def test_decode_key_b64_not_base64() -> None:
    with pytest.raises(AnonymizerKeyError):
        decode_key_b64("not base64 !!!", source="--key")
