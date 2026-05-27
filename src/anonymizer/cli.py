"""
Command-line interface for the anonymizer.

The entry point is :func:`main`, exposed via the ``anonymizer`` console
script (see ``pyproject.toml``). Calling this module as a script also
works for development::

    python -m anonymizer.cli capture.pcap
"""

from __future__ import annotations

import argparse
import logging
import sys
from typing import Optional, Sequence

from .core.config import SUPPORTED_FIELDS, AnonymizerConfig
from .core.exceptions import AnonymizerError
from .core.logging_setup import configure_logging
from .crypto.factory import build_registry
from .crypto.keys import (
    decode_key_b64,
    derive_subkeys,
    generate_master_key,
    load_key_from_file,
    save_key,
)
from .processing.orchestrator import Anonymizer
from .utils.paths import key_path_for, output_path_for
from .utils.validators import ensure_valid_pcap

logger = logging.getLogger(__name__)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="anonymizer",
        description=(
            "Anonymize (or de-anonymize) IPv4/IPv6/MAC/port fields in a "
            "Wireshark capture file using format-preserving AES-128 "
            "encryption."
        ),
    )
    parser.add_argument(
        "filename",
        help="Path to the PCAP/PCAPNG capture file.",
    )
    parser.add_argument(
        "--decrypt",
        action="store_true",
        help="De-anonymize an already-anonymized file (default: anonymize).",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=4,
        help="Number of worker threads (default: 4).",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=1000,
        help="Packets per processing batch (default: 1000).",
    )
    parser.add_argument(
        "--fields",
        nargs="+",
        choices=sorted(SUPPORTED_FIELDS),
        default=sorted(SUPPORTED_FIELDS),
        help="Which field types to (de)anonymize. Default: all of them.",
    )
    parser.add_argument(
        "--key",
        help=(
            "Base64-encoded AES-128 key. If omitted, the tool generates "
            "one on encrypt and looks for a sidecar key file on decrypt."
        ),
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"),
        help="Logging verbosity (default: INFO).",
    )
    parser.add_argument(
        "--log-file",
        help="Mirror logs to this file in addition to stderr.",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Parse arguments, run the requested operation, return a process code."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    configure_logging(level=args.log_level, logfile=args.log_file)

    try:
        ensure_valid_pcap(args.filename)
    except AnonymizerError as exc:
        logger.error("%s", exc)
        return 2

    is_encrypting = not args.decrypt
    output_path = output_path_for(args.filename, is_encrypting=is_encrypting)
    key_path = key_path_for(args.filename)

    # --- key handling -------------------------------------------------------
    try:
        if args.key:
            master_key = decode_key_b64(args.key, source="--key")
        elif is_encrypting:
            master_key = generate_master_key()
            save_key(master_key, key_path, source_filename=args.filename)
            logger.info("Generated new encryption key at %s", key_path)
        else:
            master_key = load_key_from_file(key_path)
            logger.info("Loaded decryption key from %s", key_path)
    except AnonymizerError as exc:
        logger.error("Key handling failed: %s", exc)
        return 3

    subkeys = derive_subkeys(master_key)

    # --- config + run -------------------------------------------------------
    config = AnonymizerConfig(
        num_threads=args.threads,
        batch_size=args.batch_size,
        fields=frozenset(args.fields),
        log_level=args.log_level,
    )

    try:
        config.validate()
    except ValueError as exc:
        logger.error("Bad configuration: %s", exc)
        return 4

    registry = build_registry(subkeys, config=config, is_encrypting=is_encrypting)
    anonymizer = Anonymizer(
        input_path=args.filename,
        output_path=output_path,
        registry=registry,
        config=config,
        is_encrypting=is_encrypting,
    )

    try:
        anonymizer.run()
    except AnonymizerError as exc:
        logger.error("Run aborted: %s", exc)
        return 5
    except KeyboardInterrupt:
        logger.error("Interrupted by user.")
        return 130

    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
