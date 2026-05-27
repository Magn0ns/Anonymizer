"""
High-level "cryptographer" objects: one per address type.

Each cryptographer wraps the low-level :class:`AESAddressCipher` with
two responsibilities:

* **Validation** — refuse to operate on values that don't match the
  expected format (e.g. don't try to encrypt "hello" as an IPv4).
* **Caching** — memoize results in a :class:`NetworkShardedDict` so the
  same address encountered repeatedly in a capture is encrypted/decrypted
  only once. Since the underlying cipher is deterministic, the cache is
  purely a performance optimization (correctness no longer depends on it).

The Template Method pattern keeps the common ``process()`` flow in the
base class; subclasses only fill in ``_encrypt``, ``_decrypt`` and
``_validate``.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Generic, TypeVar

from ..core.exceptions import AddressNotFoundError, CryptoError
from ..processing.sharded_dict import NetworkShardedDict
from ..utils import validators
from .aes_address import AESAddressCipher

logger = logging.getLogger(__name__)

T = TypeVar("T")  # The native type of the address (str for IP/MAC, int for ports).


class BaseAddressCryptographer(ABC, Generic[T]):
    """Template Method base class for address cryptographers.

    Subclasses implement three hooks; ``process`` orchestrates them.
    """

    def __init__(
        self,
        cipher: AESAddressCipher,
        *,
        is_encrypting: bool,
        num_shards: int,
        max_cache_entries: int = 10_000,
    ) -> None:
        self._cipher = cipher
        self._is_encrypting = is_encrypting
        # Both directions get their own cache instance — the encrypt
        # direction stores plain -> cipher, the decrypt direction stores
        # cipher -> plain. Mixing them would be wrong even though the
        # underlying cipher is symmetric.
        self._cache = NetworkShardedDict(
            num_shards=num_shards, max_cache_entries=max_cache_entries
        )

    # ------------------------------------------------------------ hooks --

    @abstractmethod
    def _validate(self, address: T) -> bool:
        """Return True iff ``address`` is well-formed for this cryptographer."""

    @abstractmethod
    def _encrypt(self, address: T) -> T:
        """Forward direction: plaintext -> ciphertext."""

    @abstractmethod
    def _decrypt(self, address: T) -> T:
        """Reverse direction: ciphertext -> plaintext."""

    @staticmethod
    def _to_cache_key(address: T) -> str:
        """Render ``address`` to the string form used as a cache key."""
        return str(address)

    # ------------------------------------------------------------ entry --

    def process(self, address: T) -> T:
        """Encrypt or decrypt ``address`` depending on the configured mode.

        Returns the input unchanged when validation fails, so the caller
        can blindly hand us anything from a packet without pre-filtering.
        Reads and writes the per-direction cache so repeated values are
        processed only once.
        """
        if address is None or address == "":
            return address

        if not self._validate(address):
            logger.debug("Skipping unrecognized address %r", address)
            return address

        key = self._to_cache_key(address)

        # Cache check.
        try:
            return self._cast_cached(self._cache.get(key))
        except AddressNotFoundError:
            pass  # Cache miss — fall through.

        # Cache miss: actually run the cipher.
        try:
            result = self._encrypt(address) if self._is_encrypting else self._decrypt(address)
        except CryptoError as exc:
            logger.warning("Crypto failure on %r: %s — returning input unchanged", address, exc)
            return address

        # Sanity-check the result; a decrypt that produces garbage is
        # the most likely failure mode and we'd rather log it than ship
        # invalid bytes downstream.
        if not self._is_encrypting and not self._validate(result):
            logger.warning(
                "Decrypted value %r does not validate; leaving %r unchanged",
                result,
                address,
            )
            return address

        self._cache.set(key, self._to_cache_key(result))
        return result

    def _cast_cached(self, cached: str) -> T:
        """Convert a cache value back to the address's native type.

        Default: assume ``T`` is ``str``. Subclasses that store integers
        (ports) override this.
        """
        return cached  # type: ignore[return-value]


# ---------------------------------------------------------------------- IPv4 --


class IPv4Cryptographer(BaseAddressCryptographer[str]):
    """IPv4-only cryptographer."""

    def _validate(self, address: str) -> bool:
        return validators.is_valid_ipv4(address)

    def _encrypt(self, address: str) -> str:
        return self._cipher.encrypt_ipv4(address)

    def _decrypt(self, address: str) -> str:
        return self._cipher.decrypt_ipv4(address)


# ---------------------------------------------------------------------- IPv6 --


class IPv6Cryptographer(BaseAddressCryptographer[str]):
    """IPv6-only cryptographer."""

    def _validate(self, address: str) -> bool:
        return validators.is_valid_ipv6(address)

    def _encrypt(self, address: str) -> str:
        return self._cipher.encrypt_ipv6(address)

    def _decrypt(self, address: str) -> str:
        return self._cipher.decrypt_ipv6(address)


# ----------------------------------------------------------------------- MAC --


class MACCryptographer(BaseAddressCryptographer[str]):
    """Cryptographer for IEEE 802 MAC addresses."""

    def _validate(self, address: str) -> bool:
        return validators.is_valid_mac(address)

    def _encrypt(self, address: str) -> str:
        return self._cipher.encrypt_mac(address)

    def _decrypt(self, address: str) -> str:
        return self._cipher.decrypt_mac(address)


# ----------------------------------------------------------------------- Port --


class PortCryptographer(BaseAddressCryptographer[int]):
    """Cryptographer for 16-bit TCP/UDP port numbers."""

    def _validate(self, address: int) -> bool:
        return validators.is_valid_port(address)

    def _encrypt(self, address: int) -> int:
        return self._cipher.encrypt_port(address)

    def _decrypt(self, address: int) -> int:
        return self._cipher.decrypt_port(address)

    def _cast_cached(self, cached: str) -> int:
        return int(cached)
