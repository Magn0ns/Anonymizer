"""
Format-preserving encryption for network identifiers.

Why this module exists
----------------------
The original anonymizer used a "truncated ECB" trick: pad the plaintext
to 16 bytes, AES-encrypt, then keep only the first N bytes as the
ciphertext. Decryption did the same thing in reverse, padding the
truncated ciphertext back up to 16 bytes and AES-decrypting.

That construction is **not actually invertible**:

    AES_decrypt(pad(AES_encrypt(pad(x))[:N])) != pad(x)

The padding suffix added on the decrypt side is different from the
ciphertext bytes that AES-encrypt produced at those positions, so
AES-decrypt yields garbage. The original tool seemed to work only
because its in-memory mapping dictionary remembered the plaintext
during the same session — close the program, reopen it to decrypt a
file, and you got nonsense back. A quick demo confirms it::

    encrypt(192.168.1.1) -> 41.80.141.59
    decrypt(41.80.141.59) -> 153.73.124.193   # WRONG, should be 192.168.1.1

This module replaces that scheme with a **Feistel network** built on
top of AES, which is the standard construction for format-preserving
encryption (FPE) on small domains. Eight rounds with a PRF round
function give us a permutation on the entire domain (32 bits for IPv4,
48 for MAC, 16 for ports, 128 for IPv6), so::

    decrypt(encrypt(x)) == x

holds unconditionally, with no lookup table. The mapping dictionary
upstream is now a pure performance cache, not a correctness crutch.

About Feistel security
----------------------
A balanced Feistel with a secure PRF round function is a strong
pseudo-random permutation after ~4 rounds (Luby-Rackoff); 8 rounds
gives a large security margin. The round function here is
``AES_K(round_no || R || 0-padding)`` truncated to ``half`` bytes,
where each address type has its own derived sub-key (see ``keys.py``).
This is essentially the construction behind FFX/FF1; we don't go all
the way to NIST FF1 because we don't need tweaks and the simpler
construction is easier to audit.
"""

from __future__ import annotations

import ipaddress
import logging
import struct
from typing import Final

from Crypto.Cipher import AES  # type: ignore

from ..core.exceptions import CryptoError
from .keys import SubKeys

logger = logging.getLogger(__name__)

_BLOCK_SIZE: Final[int] = AES.block_size  # 16
_ROUNDS: Final[int] = 8  # 4 is "secure", 8 is the safety margin we ship.

# Bit widths for each address type.
_BITS_IPV4: Final[int] = 32
_BITS_IPV6: Final[int] = 128
_BITS_MAC: Final[int] = 48
_BITS_PORT: Final[int] = 16

# IPv6 high-order bits to preserve. The top byte already distinguishes
# the major scopes that matter for traffic-analysis (ff... = multicast,
# fe80... = link-local, 2000::/3 = global unicast, 00... = unspecified
# / loopback, etc.). Keeping the full byte costs us nothing in
# anonymity and leaves us with a clean 120-bit (even) body to encrypt.
_IPV6_PREFIX_BITS: Final[int] = 8
_IPV6_PREFIX_MASK: Final[int] = ((1 << _IPV6_PREFIX_BITS) - 1) << (_BITS_IPV6 - _IPV6_PREFIX_BITS)
_IPV6_BODY_MASK: Final[int] = (1 << (_BITS_IPV6 - _IPV6_PREFIX_BITS)) - 1


def _feistel_round(key: bytes, round_no: int, half_value: int, half_bytes: int) -> int:
    """Pseudo-random round function: ``AES_K(round_no || R) >> truncate``.

    Returns ``half_bytes`` worth of pseudo-random output, suitable for
    XORing into the opposite half.
    """
    # 4-byte big-endian round counter, then the half value padded to 12
    # bytes, totaling exactly one AES block. The padding is constant per
    # round so the round function is a deterministic PRF.
    payload_bytes = max(half_bytes, 1)
    block = struct.pack(">I", round_no) + half_value.to_bytes(payload_bytes, "big")
    # Truncate or pad to one AES block.
    if len(block) > _BLOCK_SIZE:
        block = block[:_BLOCK_SIZE]
    elif len(block) < _BLOCK_SIZE:
        block = block.ljust(_BLOCK_SIZE, b"\x00")

    cipher = AES.new(key, AES.MODE_ECB)
    out = cipher.encrypt(block)
    return int.from_bytes(out[:payload_bytes], "big")


def _feistel_encrypt(key: bytes, value: int, n_bits: int, rounds: int = _ROUNDS) -> int:
    """Encrypt ``value`` (an ``n_bits``-wide integer) with a balanced Feistel.

    All our widths (32, 48, 16, 120) are even, so we keep the
    construction balanced — strictly simpler than the unbalanced case
    and avoids subtle bugs around alternating half sizes.
    """
    if n_bits < 2 or n_bits % 2 != 0:
        raise CryptoError(f"Feistel requires an even bit-width >= 2; got {n_bits}")
    half_bits = n_bits // 2
    half_mask = (1 << half_bits) - 1
    half_bytes = (half_bits + 7) // 8

    left = (value >> half_bits) & half_mask
    right = value & half_mask
    for r in range(rounds):
        new_right = left ^ (_feistel_round(key, r, right, half_bytes) & half_mask)
        left, right = right, new_right
    return (left << half_bits) | right


def _feistel_decrypt(key: bytes, value: int, n_bits: int, rounds: int = _ROUNDS) -> int:
    """Inverse of :func:`_feistel_encrypt`."""
    if n_bits < 2 or n_bits % 2 != 0:
        raise CryptoError(f"Feistel requires an even bit-width >= 2; got {n_bits}")
    half_bits = n_bits // 2
    half_mask = (1 << half_bits) - 1
    half_bytes = (half_bits + 7) // 8

    left = (value >> half_bits) & half_mask
    right = value & half_mask
    for r in reversed(range(rounds)):
        new_left = right ^ (_feistel_round(key, r, left, half_bytes) & half_mask)
        left, right = new_left, left
    return (left << half_bits) | right


class AESAddressCipher:
    """Format-preserving cipher for IPv4, IPv6, MAC and port values.

    Every method is **deterministic** (same input + key -> same output)
    and **invertible** (``decrypt(encrypt(x)) == x``). Threads can call
    the same cipher concurrently because internal state is allocated
    per call (AES contexts are not reused).
    """

    def __init__(self, subkeys: SubKeys) -> None:
        self._subkeys = subkeys

    # ---- IPv4 ---------------------------------------------------------------

    def encrypt_ipv4(self, ip: str) -> str:
        try:
            n = int(ipaddress.IPv4Address(ip))
            enc = _feistel_encrypt(self._subkeys.ipv4, n, _BITS_IPV4)
            return str(ipaddress.IPv4Address(enc))
        except (ValueError, CryptoError) as exc:
            raise CryptoError(f"IPv4 encrypt failed for {ip!r}: {exc}") from exc

    def decrypt_ipv4(self, ip: str) -> str:
        try:
            n = int(ipaddress.IPv4Address(ip))
            dec = _feistel_decrypt(self._subkeys.ipv4, n, _BITS_IPV4)
            return str(ipaddress.IPv4Address(dec))
        except (ValueError, CryptoError) as exc:
            raise CryptoError(f"IPv4 decrypt failed for {ip!r}: {exc}") from exc

    # ---- IPv6 ---------------------------------------------------------------

    def encrypt_ipv6(self, ip: str) -> str:
        """Encrypt an IPv6 address, preserving its top byte.

        The high-order byte tells us at a glance whether we're looking
        at a global unicast (2000::/3, ``20`` prefix), a link-local
        (``fe80::``), a multicast (``ff..``) or an unspecified/loopback
        address (``00``). Keeping that byte intact preserves the
        routing-level semantics of the capture while still hiding the
        identifying suffix.
        """
        try:
            n = int(ipaddress.IPv6Address(ip))
            prefix = n & _IPV6_PREFIX_MASK
            body = n & _IPV6_BODY_MASK
            enc_body = _feistel_encrypt(
                self._subkeys.ipv6, body, _BITS_IPV6 - _IPV6_PREFIX_BITS
            )
            return str(ipaddress.IPv6Address(prefix | enc_body))
        except (ValueError, CryptoError) as exc:
            raise CryptoError(f"IPv6 encrypt failed for {ip!r}: {exc}") from exc

    def decrypt_ipv6(self, ip: str) -> str:
        try:
            n = int(ipaddress.IPv6Address(ip))
            prefix = n & _IPV6_PREFIX_MASK
            body = n & _IPV6_BODY_MASK
            dec_body = _feistel_decrypt(
                self._subkeys.ipv6, body, _BITS_IPV6 - _IPV6_PREFIX_BITS
            )
            return str(ipaddress.IPv6Address(prefix | dec_body))
        except (ValueError, CryptoError) as exc:
            raise CryptoError(f"IPv6 decrypt failed for {ip!r}: {exc}") from exc

    # ---- MAC ----------------------------------------------------------------

    def encrypt_mac(self, mac: str) -> str:
        try:
            n = int(mac.replace(":", ""), 16)
            if n.bit_length() > _BITS_MAC:
                raise ValueError("MAC larger than 48 bits")
            enc = _feistel_encrypt(self._subkeys.mac, n, _BITS_MAC)
            return _format_mac(enc)
        except (ValueError, CryptoError) as exc:
            raise CryptoError(f"MAC encrypt failed for {mac!r}: {exc}") from exc

    def decrypt_mac(self, mac: str) -> str:
        try:
            n = int(mac.replace(":", ""), 16)
            if n.bit_length() > _BITS_MAC:
                raise ValueError("MAC larger than 48 bits")
            dec = _feistel_decrypt(self._subkeys.mac, n, _BITS_MAC)
            return _format_mac(dec)
        except (ValueError, CryptoError) as exc:
            raise CryptoError(f"MAC decrypt failed for {mac!r}: {exc}") from exc

    # ---- Ports --------------------------------------------------------------

    def encrypt_port(self, port: int) -> int:
        try:
            if not 0 <= port <= 0xFFFF:
                raise ValueError(f"port {port!r} out of range")
            return _feistel_encrypt(self._subkeys.port, port, _BITS_PORT)
        except (ValueError, CryptoError) as exc:
            raise CryptoError(f"Port encrypt failed for {port!r}: {exc}") from exc

    def decrypt_port(self, port: int) -> int:
        try:
            if not 0 <= port <= 0xFFFF:
                raise ValueError(f"port {port!r} out of range")
            return _feistel_decrypt(self._subkeys.port, port, _BITS_PORT)
        except (ValueError, CryptoError) as exc:
            raise CryptoError(f"Port decrypt failed for {port!r}: {exc}") from exc


def _format_mac(value: int) -> str:
    """Render a 48-bit integer as a colon-separated lowercase MAC."""
    hex_str = f"{value:012x}"
    return ":".join(hex_str[i : i + 2] for i in range(0, 12, 2))
