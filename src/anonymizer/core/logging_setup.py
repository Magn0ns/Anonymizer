"""
Logging configuration helper.

A single ``configure_logging`` entry point so the CLI, tests, and library
users all get the same format. Keeping this out of the modules themselves
lets users embed the anonymizer in a larger application without having
``logging.basicConfig`` called as a side effect of an import.
"""

from __future__ import annotations

import logging
import sys
from typing import Optional


_LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
_LOG_DATEFMT = "%Y-%m-%d %H:%M:%S"


def configure_logging(level: str = "INFO", logfile: Optional[str] = None) -> None:
    """Configure the root logger.

    Parameters
    ----------
    level:
        Standard logging level name ("DEBUG", "INFO", "WARNING", ...).
    logfile:
        Optional path; when provided, logs are mirrored to this file as
        well as to stderr. Useful for auditing long batch runs.
    """
    numeric_level = getattr(logging, level.upper(), logging.INFO)

    handlers: list[logging.Handler] = [logging.StreamHandler(stream=sys.stderr)]
    if logfile:
        handlers.append(logging.FileHandler(logfile, encoding="utf-8"))

    formatter = logging.Formatter(_LOG_FORMAT, datefmt=_LOG_DATEFMT)
    for handler in handlers:
        handler.setFormatter(formatter)

    root = logging.getLogger()
    # Wipe existing handlers so re-configuration is idempotent (matters
    # when the function is called twice, e.g. from tests).
    for h in list(root.handlers):
        root.removeHandler(h)
    for handler in handlers:
        root.addHandler(handler)
    root.setLevel(numeric_level)

    # Scapy is extremely chatty; clamp it unless the user asks for DEBUG.
    if numeric_level > logging.DEBUG:
        logging.getLogger("scapy").setLevel(logging.ERROR)
