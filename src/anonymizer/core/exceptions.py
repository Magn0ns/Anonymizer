"""
Custom exception hierarchy

A flat hierarchy of small, well-named exceptions is far easier to handle
upstream than overloading ``Exception`` or ``ValueError`` with implicit
meaning. Every exception in the project derives from
:class:`AnonymizerError` so callers can catch the entire surface with one
``except`` clause when needed.
"""

from __future__ import annotations


class AnonymizerError(Exception):
    """Base class for every exception raised by the project."""


# --- Crypto layer ------------------------------------------------------------

class CryptoError(AnonymizerError):
    """Generic cryptographic failure."""


class InvalidKeyError(CryptoError):
    """Raised when a key is malformed, the wrong length, or unreadable."""


class KeyDerivationError(CryptoError):
    """Raised when sub-keys cannot be derived from the master key."""


# --- Validation --------------------------------------------------------------

class ValidationError(AnonymizerError):
    """Raised when input data fails structural validation."""


class InvalidAddressError(ValidationError):
    """Raised when an IP/MAC/port value does not match its expected format."""


class InvalidPcapFileError(ValidationError):
    """Raised when a file is not a readable PCAP/PCAPNG capture."""


# --- Processing --------------------------------------------------------------

class ProcessingError(AnonymizerError):
    """Raised for non-recoverable errors during packet processing."""


class AddressNotFoundError(AnonymizerError):
    """Raised when a mapping lookup misses in both cache and shard."""


class ErrorThresholdExceeded(ProcessingError):
    """Raised when accumulated errors of a given severity exceed the limit."""
