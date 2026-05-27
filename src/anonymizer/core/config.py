"""
Centralized runtime configuration.

All tunables live here so they can be overridden from the CLI without
hunting through the codebase. Using a dataclass keeps the config immutable
per run and makes it trivial to inject into the components that need it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import FrozenSet


# Default field selection for anonymization: which layers/fields to touch.
# A frozenset is used so the default cannot be mutated accidentally.
DEFAULT_FIELDS: FrozenSet[str] = frozenset({"ipv4", "ipv6", "mac", "ports"})

# Supported field names (single source of truth for CLI validation).
SUPPORTED_FIELDS: FrozenSet[str] = frozenset({"ipv4", "ipv6", "mac", "ports"})


@dataclass(frozen=True)
class ErrorThresholds:
    """Maximum accumulated errors per severity before aborting the run."""

    critical: int = 100
    major: int = 500
    minor: int = 1000


@dataclass(frozen=True)
class AnonymizerConfig:
    """Immutable per-run configuration.

    Attributes
    ----------
    num_threads:
        Worker threads in the processing pool.
    batch_size:
        Packets aggregated before being submitted to a worker.
    retry_batch_size:
        Smaller batch size used when re-processing failed packets.
    max_cache_entries:
        Upper bound for the LRU hot-cache (per address-type cryptographer).
    shards_per_thread:
        Multiplier used to size the sharded dictionary (more shards =
        finer-grained locking = better concurrency, at the cost of memory).
    fields:
        Subset of ``SUPPORTED_FIELDS`` to actually anonymize.
    error_thresholds:
        Per-severity error caps that abort the run when exceeded.
    log_level:
        Logging level for the root logger (string form, e.g. "INFO").
    """

    num_threads: int = 4
    batch_size: int = 1000
    retry_batch_size: int = 100
    max_cache_entries: int = 10_000
    shards_per_thread: int = 2
    fields: FrozenSet[str] = DEFAULT_FIELDS
    error_thresholds: ErrorThresholds = field(default_factory=ErrorThresholds)
    log_level: str = "INFO"

    @property
    def num_shards(self) -> int:
        """Total number of shards in the sharded address dictionary."""
        return max(1, self.num_threads * self.shards_per_thread)

    def validate(self) -> None:
        """Sanity-check the configuration; raises ``ValueError`` on failure."""
        if self.num_threads < 1:
            raise ValueError("num_threads must be >= 1")
        if self.batch_size < 1:
            raise ValueError("batch_size must be >= 1")
        if self.retry_batch_size < 1:
            raise ValueError("retry_batch_size must be >= 1")
        if self.max_cache_entries < 0:
            raise ValueError("max_cache_entries must be >= 0")
        unknown = self.fields - SUPPORTED_FIELDS
        if unknown:
            raise ValueError(f"Unknown fields requested: {sorted(unknown)}")
