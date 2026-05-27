"""
Sharded, thread-safe address dictionary with an LRU hot cache.

The structure has two layers:

1. **Hot cache** — a small LRU on top, hit first; guarded by one lock.
2. **Shards** — N independent dictionaries, each behind its own ``RLock``,
   selected by a deterministic function of the key.

The win is that writes/reads on different shards don't contend, and
repeated accesses to the same address avoid the shard entirely.

Locking order is strict to avoid deadlocks:

    shard.lock  ->  hot_cache.lock

Never the other way around.
"""

from __future__ import annotations

import ipaddress
import logging
import threading
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple

from ..core.exceptions import AddressNotFoundError
from ..utils.validators import is_valid_ip, is_valid_mac, is_valid_port

logger = logging.getLogger(__name__)


@dataclass
class _Shard:
    """A single shard: a dict plus its own reentrant lock."""

    data: Dict[str, str] = field(default_factory=dict)
    lock: threading.RLock = field(default_factory=threading.RLock)


class NetworkShardedDict:
    """A sharded address-mapping dictionary with an LRU hot cache.

    Parameters
    ----------
    num_shards:
        How many shards to create. More shards = less contention but
        higher memory overhead.
    max_cache_entries:
        Upper bound for the hot cache. Set to 0 to disable caching.
    """

    def __init__(self, num_shards: int, max_cache_entries: int = 10_000) -> None:
        if num_shards < 1:
            raise ValueError("num_shards must be >= 1")
        if max_cache_entries < 0:
            raise ValueError("max_cache_entries must be >= 0")

        self._shards: list[_Shard] = [_Shard() for _ in range(num_shards)]
        self._hot_cache: "OrderedDict[str, Tuple[int, str]]" = OrderedDict()
        self._cache_lock = threading.RLock()
        self._max_cache_entries = max_cache_entries

    # ------------------------------------------------------------------ helpers

    def _shard_index(self, address: str) -> int:
        """Pick a shard for ``address`` based on its type.

        We bias the shard function so semantically related addresses
        (same /24 IPv4 subnet, same vendor MAC prefix, similar port
        numbers) land on different shards for better parallelism.
        """
        n = len(self._shards)
        try:
            if is_valid_ip(address):
                ip = ipaddress.ip_address(address)
                if isinstance(ip, ipaddress.IPv4Address):
                    # Last octet — varies the most across a subnet.
                    return int(address.rsplit(".", 1)[-1]) % n
                # IPv6: last 16 bits of the packed representation.
                return int.from_bytes(ip.packed[-2:], "big") % n

            if is_valid_mac(address):
                parts = address.split(":")
                # NIC-specific bytes are the last three, ignoring OUI.
                return (
                    int(parts[-3], 16) + int(parts[-2], 16) + int(parts[-1], 16)
                ) % n

            # Ports are stored as strings here; parse if numeric.
            if address.isdigit() and is_valid_port(int(address)):
                return int(address) % n

            # Fallback for anything unexpected.
            return hash(address) % n
        except (ValueError, IndexError) as exc:
            logger.warning("Shard calculation fell back to hash() for %r: %s", address, exc)
            return hash(address) % n

    def _bump_cache(self, address: str, shard_idx: int, value: str) -> None:
        """Insert/update an entry in the LRU. Caller must hold ``_cache_lock``."""
        if self._max_cache_entries == 0:
            return
        if address in self._hot_cache:
            del self._hot_cache[address]
        elif len(self._hot_cache) >= self._max_cache_entries:
            self._hot_cache.popitem(last=False)  # Evict LRU
        self._hot_cache[address] = (shard_idx, value)

    # ------------------------------------------------------------------- public

    def get(self, address: str) -> str:
        """Return the value mapped to ``address`` or raise."""
        if not address:
            raise ValueError("address cannot be empty")

        # Fast path: hot cache (no shard lock needed).
        with self._cache_lock:
            cached = self._hot_cache.get(address)
            if cached is not None:
                self._hot_cache.move_to_end(address)
                return cached[1]

        # Slow path: lock the shard, look in its dict, populate cache.
        shard_idx = self._shard_index(address)
        shard = self._shards[shard_idx]

        with shard.lock:
            value = shard.data.get(address)
            if value is None:
                raise AddressNotFoundError(f"Address not found: {address!r}")
            # Update cache *after* releasing shard lock by holding both
            # in the documented order.
            with self._cache_lock:
                self._bump_cache(address, shard_idx, value)
            return value

    def set(self, address: str, value: str) -> None:
        """Map ``address`` -> ``value``, replacing any existing entry."""
        if not address:
            raise ValueError("address cannot be empty")
        if not isinstance(value, str):
            raise TypeError("value must be a str")

        shard_idx = self._shard_index(address)
        shard = self._shards[shard_idx]

        # Strict lock order: shard, then cache.
        with shard.lock:
            shard.data[address] = value
            with self._cache_lock:
                self._bump_cache(address, shard_idx, value)

    def __contains__(self, address: str) -> bool:
        try:
            self.get(address)
            return True
        except AddressNotFoundError:
            return False

    def __len__(self) -> int:
        return sum(len(s.data) for s in self._shards)
