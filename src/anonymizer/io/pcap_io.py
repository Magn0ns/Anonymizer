"""
Thread-safe pcap writer wrapping scapy's append-mode ``wrpcap``.

Scapy's ``wrpcap(..., append=True)`` is not safe to call concurrently
on the same file: each invocation reopens the file and writes the
pcap header if it thinks the file is empty. Wrapping it in a single
mutex turns it into a safe writer at the cost of serializing the
actual disk writes — which is what we want anyway, since the heavy
work is the crypto, not the write.
"""

from __future__ import annotations

import logging
import threading
from typing import Iterable, List

from scapy.packet import Packet  # type: ignore
from scapy.utils import wrpcap  # type: ignore

logger = logging.getLogger(__name__)


class ThreadSafePcapWriter:
    """A drop-in wrapper around ``wrpcap`` with a single write lock."""

    def __init__(self, path: str) -> None:
        self._path = path
        self._lock = threading.Lock()
        # Create an empty pcap file up front so ``append=True`` always
        # has a real file header to append to and concurrent writers
        # never race on file creation.
        wrpcap(self._path, [])
        logger.debug("Initialized empty pcap at %s", self._path)

    @property
    def path(self) -> str:
        return self._path

    def write(self, packets: Iterable[Packet]) -> int:
        """Append the given packets, returning how many were actually written."""
        packets_list: List[Packet] = [p for p in packets if p is not None]
        if not packets_list:
            return 0
        with self._lock:
            wrpcap(self._path, packets_list, append=True)
        logger.debug("Wrote %d packets to %s", len(packets_list), self._path)
        return len(packets_list)
