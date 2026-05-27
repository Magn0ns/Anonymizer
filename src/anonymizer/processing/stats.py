"""
Thread-safe accounting: counts of processed/failed packets and errors.

The original code mixed stats tracking, error counting, and threshold
enforcement into the main ``PacketCryptographer``. Pulling these out
makes the orchestration loop easier to follow and the bookkeeping
classes trivially unit-testable.
"""

from __future__ import annotations

import logging
import threading
from collections import defaultdict
from dataclasses import dataclass
from typing import DefaultDict

from ..core.config import ErrorThresholds
from ..core.exceptions import ErrorThresholdExceeded

logger = logging.getLogger(__name__)


@dataclass
class ProcessingStats:
    """Coarse-grained run statistics."""

    total_packets: int = 0
    processed_packets: int = 0
    retry_count: int = 0


class StatsTracker:
    """Thread-safe wrapper over :class:`ProcessingStats`."""

    def __init__(self) -> None:
        self._stats = ProcessingStats()
        self._lock = threading.Lock()

    def increment_total(self, n: int = 1) -> None:
        with self._lock:
            self._stats.total_packets += n

    def increment_processed(self, n: int = 1) -> int:
        """Return the new ``processed_packets`` value, for progress logging."""
        with self._lock:
            self._stats.processed_packets += n
            return self._stats.processed_packets

    def increment_retries(self, n: int = 1) -> int:
        with self._lock:
            self._stats.retry_count += n
            return self._stats.retry_count

    def snapshot(self) -> ProcessingStats:
        """Return an unlocked copy of the current stats."""
        with self._lock:
            return ProcessingStats(
                total_packets=self._stats.total_packets,
                processed_packets=self._stats.processed_packets,
                retry_count=self._stats.retry_count,
            )


class ErrorTracker:
    """Counts errors by severity and trips when a threshold is reached.

    The thresholds come from :class:`ErrorThresholds`. The tracker is a
    thread-safe counter — every increment is logged but only the
    threshold-crossing increment raises :class:`ErrorThresholdExceeded`,
    which the orchestrator catches and turns into a clean shutdown.
    """

    SEVERITIES = ("critical", "major", "minor")

    def __init__(self, thresholds: ErrorThresholds) -> None:
        self._thresholds = thresholds
        self._counts: DefaultDict[str, int] = defaultdict(int)
        self._lock = threading.Lock()
        self._stop_event = threading.Event()

    @property
    def should_stop(self) -> threading.Event:
        """Set when a threshold is crossed; workers can poll this."""
        return self._stop_event

    def record(self, severity: str, error: Exception) -> None:
        """Record an error of the given severity.

        Raises :class:`ErrorThresholdExceeded` when the per-severity
        limit is reached. The very first cross sets ``should_stop`` so
        any thread checking that flag can bail out promptly.
        """
        if severity not in self.SEVERITIES:
            raise ValueError(f"Unknown severity {severity!r}")

        threshold = getattr(self._thresholds, severity)
        with self._lock:
            self._counts[severity] += 1
            count = self._counts[severity]

        if count % 100 == 0 and count < threshold:
            logger.warning("Accumulated %d %s errors", count, severity)

        if count >= threshold:
            self._stop_event.set()
            raise ErrorThresholdExceeded(
                f"Too many {severity} errors ({count} >= {threshold}). "
                f"Last error: {error}"
            )

    def summary(self) -> dict[str, int]:
        """Return a snapshot of error counts."""
        with self._lock:
            return dict(self._counts)
