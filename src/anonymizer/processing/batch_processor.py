"""
Batch aggregation and retry orchestration for parallel packet processing.

The trade-off this module exposes is "fewer, larger batches" vs.
"more, smaller batches":

* Large batches amortize thread-dispatch overhead but make retries
  expensive (a single bad packet drags the whole batch into a retry).
* Small batches give us finer error isolation at the cost of more
  dispatch work.

The compromise is to use the configured ``batch_size`` for first-pass
processing and a smaller ``retry_batch_size`` on the second pass.
"""

from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Callable, List, Optional

from scapy.packet import Packet  # type: ignore

logger = logging.getLogger(__name__)


@dataclass
class BatchResult:
    """Outcome of a single batch submission."""

    processed_packets: List[Packet] = field(default_factory=list)
    failed_packets: List[Packet] = field(default_factory=list)
    errors: List[Exception] = field(default_factory=list)
    elapsed_seconds: float = 0.0


# Type aliases for readability.
ProcessFn = Callable[[List[Packet]], BatchResult]
WriteFn = Callable[[BatchResult], None]


class BatchAccumulator:
    """Thread-safe packet accumulator that emits full batches.

    The reader loop calls ``add`` for every packet; whenever the
    current batch fills up, ``add`` returns the list so the caller
    can submit it for processing.
    """

    def __init__(self, batch_size: int = 1000) -> None:
        if batch_size < 1:
            raise ValueError("batch_size must be >= 1")
        self._batch_size = batch_size
        self._current: List[Packet] = []
        self._lock = threading.Lock()

    def add(self, packet: Packet) -> Optional[List[Packet]]:
        """Append ``packet`` and return a full batch if one is ready."""
        with self._lock:
            self._current.append(packet)
            if len(self._current) >= self._batch_size:
                batch, self._current = self._current, []
                return batch
        return None

    def drain(self) -> List[Packet]:
        """Return any packets currently buffered (may be empty)."""
        with self._lock:
            batch, self._current = self._current, []
            return batch


class BatchProcessor:
    """Run :class:`BatchResult`-producing functions on a thread pool, with retries."""

    def __init__(self, pool: ThreadPoolExecutor) -> None:
        self._pool = pool

    def run_batch(
        self,
        batch: List[Packet],
        *,
        process: ProcessFn,
        writer: WriteFn,
    ) -> List[Packet]:
        """Submit one batch, write the results, return the failures."""
        future = self._pool.submit(process, batch)
        result = future.result()
        writer(result)
        return result.failed_packets

    def retry_until_drained(
        self,
        failed: List[Packet],
        *,
        process: ProcessFn,
        writer: WriteFn,
        retry_batch_size: int = 100,
        on_attempt: Optional[Callable[[int, int], None]] = None,
    ) -> List[Packet]:
        """Re-process ``failed`` packets until none fail or no progress is made.

        The retry loop bails out the moment an attempt produces the same
        number of failures as the previous attempt — i.e. when retrying
        is no longer making progress. That guards against an infinite
        loop on genuinely unprocessable packets (e.g. truncated frames).
        """
        attempt = 0
        while failed:
            attempt += 1
            if on_attempt is not None:
                on_attempt(attempt, len(failed))
            logger.info(
                "Retry attempt #%d for %d failed packets (batch size %d)",
                attempt,
                len(failed),
                retry_batch_size,
            )

            new_failed: List[Packet] = []
            for i in range(0, len(failed), retry_batch_size):
                chunk = failed[i : i + retry_batch_size]
                new_failed.extend(self.run_batch(chunk, process=process, writer=writer))

            # If we didn't make any progress, stop — these packets are
            # genuinely unprocessable and looping forever helps no one.
            if len(new_failed) >= len(failed):
                logger.warning(
                    "Retry #%d made no progress (%d -> %d failures); "
                    "giving up on remaining packets",
                    attempt,
                    len(failed),
                    len(new_failed),
                )
                return new_failed

            failed = new_failed
            # Small back-off so we don't hammer a struggling system.
            time.sleep(min(attempt * 0.1, 1.0))

        return failed
