"""Anonymizer — format-preserving anonymization of Wireshark captures."""

from .core.config import AnonymizerConfig
from .core.exceptions import (
    AnonymizerError,
    CryptoError,
    InvalidKeyError,
    InvalidPcapFileError,
    ProcessingError,
    ValidationError,
)

__version__ = "2.0.0"
__all__ = [
    "AnonymizerConfig",
    "AnonymizerError",
    "CryptoError",
    "InvalidKeyError",
    "InvalidPcapFileError",
    "ProcessingError",
    "ValidationError",
    "__version__",
]
