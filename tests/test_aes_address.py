"""Unit tests for the Feistel-based address cipher.

These tests assert the property that the original code silently
violated: ``decrypt(encrypt(x)) == x`` for every supported domain.
"""

from __future__ import annotations

import ipaddress

import pytest

from anonymizer.core.exceptions import CryptoError
from anonymizer.crypto.aes_address import AESAddressCipher
from anonymizer.crypto.keys import derive_subkeys, generate_master_key


@pytest.fixture()
def cipher() -> AESAddressCipher:
    key = generate_master_key()
    return AESAddressCipher(derive_subkeys(key))


# --- IPv4 --------------------------------------------------------------------

@pytest.mark.parametrize(
    "ip",
    [
        "0.0.0.0",
        "127.0.0.1",
        "192.168.1.1",
        "10.0.0.42",
        "255.255.255.255",
        "8.8.8.8",
    ],
)
def test_ipv4_roundtrip(cipher: AESAddressCipher, ip: str) -> None:
    """Every IPv4 address round-trips back to itself."""
    encrypted = cipher.encrypt_ipv4(ip)
    assert encrypted != ip  # Must actually change the value.
    assert cipher.decrypt_ipv4(encrypted) == ip


def test_ipv4_deterministic(cipher: AESAddressCipher) -> None:
    """The same plaintext always produces the same ciphertext."""
    assert cipher.encrypt_ipv4("10.0.0.1") == cipher.encrypt_ipv4("10.0.0.1")


def test_ipv4_distinguishes(cipher: AESAddressCipher) -> None:
    """Different plaintexts produce different ciphertexts."""
    assert cipher.encrypt_ipv4("10.0.0.1") != cipher.encrypt_ipv4("10.0.0.2")


def test_ipv4_rejects_invalid(cipher: AESAddressCipher) -> None:
    with pytest.raises(CryptoError):
        cipher.encrypt_ipv4("not-an-ip")


# --- IPv6 --------------------------------------------------------------------

@pytest.mark.parametrize(
    "ip",
    [
        "::1",
        "2001:db8::1",
        "fe80::1",
        "ff02::1",
        "::",
        "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
    ],
)
def test_ipv6_roundtrip(cipher: AESAddressCipher, ip: str) -> None:
    encrypted = cipher.encrypt_ipv6(ip)
    decrypted = cipher.decrypt_ipv6(encrypted)
    # Compare numerically because string forms can differ in compression.
    assert ipaddress.IPv6Address(decrypted) == ipaddress.IPv6Address(ip)


@pytest.mark.parametrize(
    "ip,expected_top_byte",
    [
        ("fe80::1", 0xFE),
        ("ff02::1", 0xFF),
        ("2001:db8::1", 0x20),
        ("::1", 0x00),
    ],
)
def test_ipv6_preserves_top_byte(
    cipher: AESAddressCipher, ip: str, expected_top_byte: int
) -> None:
    """High-order byte is preserved to keep scope semantics intact."""
    encrypted = cipher.encrypt_ipv6(ip)
    enc_byte = ipaddress.IPv6Address(encrypted).packed[0]
    assert enc_byte == expected_top_byte


# --- MAC ---------------------------------------------------------------------

@pytest.mark.parametrize(
    "mac",
    [
        "00:00:00:00:00:00",
        "ff:ff:ff:ff:ff:ff",
        "00:11:22:33:44:55",
        "de:ad:be:ef:ca:fe",
    ],
)
def test_mac_roundtrip(cipher: AESAddressCipher, mac: str) -> None:
    encrypted = cipher.encrypt_mac(mac)
    assert cipher.decrypt_mac(encrypted) == mac.lower()


def test_mac_output_is_canonical(cipher: AESAddressCipher) -> None:
    """Output should always be lowercase, colon-separated."""
    encrypted = cipher.encrypt_mac("DE:AD:BE:EF:CA:FE")
    assert encrypted == encrypted.lower()
    assert encrypted.count(":") == 5


# --- Ports -------------------------------------------------------------------

@pytest.mark.parametrize("port", [0, 1, 80, 443, 8080, 12345, 65535])
def test_port_roundtrip(cipher: AESAddressCipher, port: int) -> None:
    encrypted = cipher.encrypt_port(port)
    assert 0 <= encrypted <= 65535
    assert cipher.decrypt_port(encrypted) == port


def test_port_out_of_range(cipher: AESAddressCipher) -> None:
    with pytest.raises(CryptoError):
        cipher.encrypt_port(70000)


# --- Determinism across cipher instances -------------------------------------

def test_same_key_same_results() -> None:
    """Two cipher instances built from the same master key must agree."""
    master = generate_master_key()
    sk1 = derive_subkeys(master)
    sk2 = derive_subkeys(master)
    c1 = AESAddressCipher(sk1)
    c2 = AESAddressCipher(sk2)
    assert c1.encrypt_ipv4("10.0.0.1") == c2.encrypt_ipv4("10.0.0.1")
    assert c1.encrypt_mac("00:11:22:33:44:55") == c2.encrypt_mac("00:11:22:33:44:55")


def test_different_keys_different_results() -> None:
    sk1 = derive_subkeys(generate_master_key())
    sk2 = derive_subkeys(generate_master_key())
    c1 = AESAddressCipher(sk1)
    c2 = AESAddressCipher(sk2)
    # With overwhelming probability, different keys produce different
    # ciphertexts for the same plaintext.
    assert c1.encrypt_ipv4("10.0.0.1") != c2.encrypt_ipv4("10.0.0.1")
