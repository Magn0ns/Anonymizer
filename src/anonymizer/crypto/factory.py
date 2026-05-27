"""
Factory bundling the four cryptographers needed by a single processing run.

The factory exists so the rest of the code (the packet processor, in
particular) can take a single, opaque "registry" object rather than a
fistful of cryptographer instances. It also gives us a clean place to
honour ``config.fields`` — if the user only wants IPv4 anonymized, the
other cryptographers are simply absent from the registry.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from ..core.config import AnonymizerConfig
from .aes_address import AESAddressCipher
from .cryptographers import (
    IPv4Cryptographer,
    IPv6Cryptographer,
    MACCryptographer,
    PortCryptographer,
)
from .keys import SubKeys


@dataclass
class CryptographerRegistry:
    """Bundle of (optional) per-field cryptographers.

    A field set to ``None`` means "the user opted out of anonymizing
    this field type". Callers should check for ``None`` and pass values
    through unchanged in that case.
    """

    ipv4: Optional[IPv4Cryptographer]
    ipv6: Optional[IPv6Cryptographer]
    mac: Optional[MACCryptographer]
    port: Optional[PortCryptographer]


def build_registry(
    subkeys: SubKeys,
    *,
    config: AnonymizerConfig,
    is_encrypting: bool,
) -> CryptographerRegistry:
    """Build a :class:`CryptographerRegistry` honouring ``config.fields``.

    The same :class:`AESAddressCipher` is shared by every cryptographer
    — it's stateless beyond holding the sub-keys, so a single instance
    is both safe and the lighter option.
    """
    cipher = AESAddressCipher(subkeys)
    kwargs = dict(
        cipher=cipher,
        is_encrypting=is_encrypting,
        num_shards=config.num_shards,
        max_cache_entries=config.max_cache_entries,
    )
    return CryptographerRegistry(
        ipv4=IPv4Cryptographer(**kwargs) if "ipv4" in config.fields else None,
        ipv6=IPv6Cryptographer(**kwargs) if "ipv6" in config.fields else None,
        mac=MACCryptographer(**kwargs) if "mac" in config.fields else None,
        port=PortCryptographer(**kwargs) if "ports" in config.fields else None,
    )
