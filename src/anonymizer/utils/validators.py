"""
Stateless validation helpers.

These helpers do not raise on a "no" answer; they return ``False``. Use
``ensure_valid_pcap`` when you want failures to bubble up as exceptions.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
from typing import Final

from ..core.exceptions import InvalidPcapFileError

logger = logging.getLogger(__name__)

# Pre-compiled once at import time: cheaper than recompiling on every call.
_MAC_RE: Final = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")

# IANA-defined upper bound for a TCP/UDP port number (16-bit unsigned).
PORT_MIN: Final[int] = 0
PORT_MAX: Final[int] = 65_535

_VALID_PCAP_EXTENSIONS: Final = (".pcap", ".pcapng")


def is_valid_ipv4(address: str) -> bool:
    """Return True iff ``address`` is a well-formed IPv4 dotted-quad."""
    if not address:
        return False
    try:
        return isinstance(ipaddress.ip_address(address), ipaddress.IPv4Address)
    except ValueError:
        return False


def is_valid_ipv6(address: str) -> bool:
    """Return True iff ``address`` is a well-formed IPv6 address."""
    if not address:
        return False
    try:
        return isinstance(ipaddress.ip_address(address), ipaddress.IPv6Address)
    except ValueError:
        return False


def is_valid_ip(address: str) -> bool:
    """Return True iff ``address`` is a valid IPv4 *or* IPv6 address."""
    return is_valid_ipv4(address) or is_valid_ipv6(address)


def is_valid_mac(address: str) -> bool:
    """Return True iff ``address`` matches the canonical MAC notation."""
    if not address:
        return False
    return bool(_MAC_RE.match(address))


def is_valid_port(port: object) -> bool:
    """Return True iff ``port`` is an int in [0, 65535]."""
    if isinstance(port, bool):  # bool is a subclass of int — exclude it.
        return False
    if not isinstance(port, int):
        return False
    return PORT_MIN <= port <= PORT_MAX


def has_valid_extension(filepath: str) -> bool:
    """Return True iff the file extension is .pcap or .pcapng."""
    return os.path.splitext(filepath)[1].lower() in _VALID_PCAP_EXTENSIONS


def ensure_valid_pcap(filepath: str) -> None:
    """Validate a capture file or raise :class:`InvalidPcapFileError`.

    The function performs three checks in order: existence, extension,
    readability of the first packet. The readability check is what
    actually rules out e.g. truncated or text files that happen to have
    the right extension.
    """
    if not os.path.exists(filepath):
        raise InvalidPcapFileError(f"File not found: {filepath}")

    if not has_valid_extension(filepath):
        raise InvalidPcapFileError(
            f"Unsupported file extension for {filepath!r}; expected "
            f"one of {_VALID_PCAP_EXTENSIONS}"
        )

    # Imported lazily so importing this module doesn't trigger scapy's
    # heavy import side effects in environments that don't need pcap.
    from scapy.utils import PcapReader  # type: ignore

    try:
        with PcapReader(filepath) as reader:
            next(reader)
    except StopIteration:
        # An empty capture file isn't malformed; warn but accept it.
        logger.warning("Capture file %s contains no packets.", filepath)
    except Exception as exc:  # noqa: BLE001 - scapy raises various types
        raise InvalidPcapFileError(f"Invalid PCAP file {filepath!r}: {exc}") from exc
