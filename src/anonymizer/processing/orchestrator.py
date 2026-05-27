"""
Top-level orchestrator: ties together I/O, batching, the thread pool,
the transformer, stats, and the retry loop.

This is the only module in the project that "knows" how all the pieces
fit together. Every other module exposes a focused API; this one wires
them up.
"""

from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor
from typing import List

from scapy.packet import Packet  # type: ignore
from scapy.utils import PcapReader  # type: ignore

from ..core.config import AnonymizerConfig
from ..core.exceptions import ErrorThresholdExceeded
from ..crypto.factory import CryptographerRegistry
from ..io.pcap_io import ThreadSafePcapWriter
from ..io.pcap_writer import atomic_pcap_writer
from .batch_processor import BatchAccumulator, BatchProcessor, BatchResult
from .packet_transformer import PacketTransformer
from .stats import ErrorTracker, StatsTracker

logger = logging.getLogger(__name__)


_PROGRESS_INTERVAL = 1000  # Log progress every N processed packets.


class Anonymizer:
    """Run anonymization (or de-anonymization) over a pcap file."""

    def __init__(
        self,
        input_path: str,
        output_path: str,
        registry: CryptographerRegistry,
        *,
        config: AnonymizerConfig,
        is_encrypting: bool,
    ) -> None:
        config.validate()
        self._input_path = input_path
        self._output_path = output_path
        self._config = config
        self._is_encrypting = is_encrypting

        self._transformer = PacketTransformer(registry)
        self._stats = StatsTracker()
        self._errors = ErrorTracker(config.error_thresholds)
        self._accumulator = BatchAccumulator(batch_size=config.batch_size)

        # Created in run() because we want a fresh pool per invocation.
        self._pool: ThreadPoolExecutor | None = None
        self._writer: ThreadSafePcapWriter | None = None
        self._batch_runner: BatchProcessor | None = None

    # ------------------------------------------------------------- entry --

    def run(self) -> None:
        op = "encryption" if self._is_encrypting else "decryption"
        logger.info("Starting %s of %s -> %s", op, self._input_path, self._output_path)
        start = time.monotonic()

        with atomic_pcap_writer(self._output_path) as temp_path:
            self._writer = ThreadSafePcapWriter(temp_path)
            self._pool = ThreadPoolExecutor(
                max_workers=self._config.num_threads,
                thread_name_prefix="anon-worker",
            )
            self._batch_runner = BatchProcessor(self._pool)

            try:
                failed = self._first_pass()
                if failed:
                    self._retry_pass(failed)
                logger.info("%s complete in %.2fs", op.capitalize(), time.monotonic() - start)
            finally:
                self._pool.shutdown(wait=True)
                summary = self._errors.summary()
                if summary:
                    logger.warning("Error summary: %s", summary)
                self._log_stats()

    # ------------------------------------------------------------- passes --

    def _first_pass(self) -> List[Packet]:
        """Stream the input pcap once, batching and submitting as we go."""
        failed: List[Packet] = []
        with PcapReader(self._input_path) as reader:
            for packet in reader:
                if self._errors.should_stop.is_set():
                    logger.error("Stopping early due to error threshold")
                    break
                self._stats.increment_total()
                completed = self._accumulator.add(packet)
                if completed is not None:
                    failed.extend(self._submit(completed))

        # Drain any partial last batch.
        remaining = self._accumulator.drain()
        if remaining:
            failed.extend(self._submit(remaining))
        return failed

    def _retry_pass(self, failed: List[Packet]) -> None:
        assert self._batch_runner is not None  # for type checkers

        def on_attempt(attempt: int, count: int) -> None:
            self._stats.increment_retries()

        leftover = self._batch_runner.retry_until_drained(
            failed,
            process=self._process_batch,
            writer=self._write_batch_result,
            retry_batch_size=self._config.retry_batch_size,
            on_attempt=on_attempt,
        )
        if leftover:
            logger.warning(
                "%d packets remain unprocessable after retries; "
                "they are NOT present in the output file",
                len(leftover),
            )

    # ----------------------------------------------------- batch lifecycle --

    def _submit(self, batch: List[Packet]) -> List[Packet]:
        assert self._batch_runner is not None
        return self._batch_runner.run_batch(
            batch,
            process=self._process_batch,
            writer=self._write_batch_result,
        )

    def _process_batch(self, batch: List[Packet]) -> BatchResult:
        """Run inside a worker thread: anonymize a batch of packets."""
        start = time.monotonic()
        processed: List[Packet] = []
        failed: List[Packet] = []
        errors: List[Exception] = []

        for packet in batch:
            if self._errors.should_stop.is_set():
                # Don't mark these as failed — they were never attempted.
                break
            try:
                modified, new_packet = self._transformer.transform(packet)
            except Exception as exc:  # noqa: BLE001
                failed.append(packet)
                errors.append(exc)
                try:
                    self._errors.record("major", exc)
                except ErrorThresholdExceeded as exc2:
                    errors.append(exc2)
                    break
                continue

            if modified and new_packet is not None:
                processed.append(new_packet)
                current = self._stats.increment_processed()
                self._log_progress_maybe(current)
            elif not modified:
                # The packet had no fields to anonymize — pass through.
                # We still write it to the output to preserve the
                # stream's ordering and completeness.
                processed.append(packet)
                current = self._stats.increment_processed()
                self._log_progress_maybe(current)
            else:
                # transform() returned (True, None) which is the explicit
                # "this failed" signal.
                failed.append(packet)
                try:
                    self._errors.record("minor", Exception("transform returned None"))
                except ErrorThresholdExceeded:
                    break

        elapsed = time.monotonic() - start
        return BatchResult(processed, failed, errors, elapsed)

    def _write_batch_result(self, result: BatchResult) -> None:
        if not result.processed_packets:
            return
        assert self._writer is not None
        try:
            self._writer.write(result.processed_packets)
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to write batch: %s", exc)
            self._errors.record("critical", exc)

    # -------------------------------------------------------------- utils --

    def _log_progress_maybe(self, processed: int) -> None:
        if processed % _PROGRESS_INTERVAL != 0:
            return
        snap = self._stats.snapshot()
        if snap.total_packets:
            pct = (processed / snap.total_packets) * 100
            logger.info("Progress: %.1f%% (%d/%d)", pct, processed, snap.total_packets)
        else:
            logger.info("Processed %d packets", processed)

    def _log_stats(self) -> None:
        snap = self._stats.snapshot()
        logger.info(
            "Final stats: total=%d processed=%d retries=%d",
            snap.total_packets,
            snap.processed_packets,
            snap.retry_count,
        )
