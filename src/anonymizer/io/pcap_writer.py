"""
Atomic, transactional PCAP output via a temp-file + ``os.replace`` swap.

Why bother? Two reasons:

1. If the program crashes (or is killed) mid-run, the user is left
   with the original capture untouched and a stale ``.tmp`` they can
   delete. They never end up with a half-written output that quietly
   looks valid because it has a pcap header but missing packets.

2. ``os.replace`` is atomic on the same filesystem on all the OSes we
   target — the swap to the final name is either complete or hasn't
   happened. ``shutil.move`` (used in the original code) is not always
   atomic when crossing filesystems.

The context manager yields the path of the temporary file. The caller
writes into it freely; on a clean ``__exit__`` we rename it into place,
on an exception we delete it.
"""

from __future__ import annotations

import logging
import os
import sys
from contextlib import contextmanager
from typing import Iterator

logger = logging.getLogger(__name__)


@contextmanager
def atomic_pcap_writer(
    output_path: str,
    *,
    overwrite_prompt: bool = True,
) -> Iterator[str]:
    """Yield a temp path; on clean exit, rename it to ``output_path``.

    Parameters
    ----------
    output_path:
        Final destination filename.
    overwrite_prompt:
        If ``True`` and the destination already exists, ask the user
        on stdin whether to overwrite. Programs without a TTY (CI,
        pipelines) should pass ``False`` and decide upstream.
    """
    if os.path.exists(output_path):
        if overwrite_prompt:
            if not _confirm_overwrite(output_path):
                logger.info("User declined overwrite; aborting.")
                sys.exit(0)
        # If the user accepted, or if prompting is disabled, we'll
        # replace the file on commit.

    temp_path = f"{output_path}.tmp"

    # Belt-and-braces: remove any leftover temp file from a previous
    # aborted run before we start writing.
    if os.path.exists(temp_path):
        try:
            os.remove(temp_path)
            logger.info("Removed stale temp file %s", temp_path)
        except OSError as exc:
            logger.warning("Could not remove stale temp file %s: %s", temp_path, exc)

    success = False
    try:
        yield temp_path
        success = True
    finally:
        if success:
            try:
                os.replace(temp_path, output_path)
                logger.info("Atomically committed output to %s", output_path)
            except OSError as exc:
                logger.error("Failed to commit %s -> %s: %s", temp_path, output_path, exc)
                # Try to clean up the temp file but don't mask the real error.
                _safe_remove(temp_path)
                raise
        else:
            logger.error("Run aborted with an error; cleaning up %s", temp_path)
            _safe_remove(temp_path)


def _confirm_overwrite(path: str) -> bool:
    """Prompt the user; returns True if they consent to overwriting."""
    print(f"\nFile already exists at:\n  {path}")
    while True:
        response = input("Overwrite? [y/N]: ").strip().lower()
        if response in ("y", "yes"):
            return True
        if response in ("n", "no", ""):
            return False
        print("Please answer 'y' or 'n'.")


def _safe_remove(path: str) -> None:
    if not os.path.exists(path):
        return
    try:
        os.remove(path)
    except OSError as exc:
        logger.warning("Failed to remove %s: %s", path, exc)
