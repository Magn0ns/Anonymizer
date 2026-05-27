"""
Example: use the anonymizer as a Python library, not via the CLI.

Run from the project root::

    PYTHONPATH=src python examples/library_usage.py path/to/capture.pcapng
"""

from __future__ import annotations

import sys
from pathlib import Path

from anonymizer.core.config import AnonymizerConfig
from anonymizer.crypto.factory import build_registry
from anonymizer.crypto.keys import derive_subkeys, generate_master_key, save_key
from anonymizer.processing.orchestrator import Anonymizer
from anonymizer.utils.paths import key_path_for, output_path_for


def anonymize(input_path: str) -> tuple[str, str]:
    """Anonymize *input_path*, returning ``(output_path, key_path)``."""
    output_path = output_path_for(input_path, is_encrypting=True)
    key_path = key_path_for(input_path)

    master = generate_master_key()
    save_key(master, key_path, source_filename=input_path)

    subkeys = derive_subkeys(master)
    config = AnonymizerConfig(num_threads=4, batch_size=1000)
    registry = build_registry(subkeys, config=config, is_encrypting=True)

    Anonymizer(
        input_path=input_path,
        output_path=output_path,
        registry=registry,
        config=config,
        is_encrypting=True,
    ).run()

    return output_path, key_path


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <capture.pcapng>", file=sys.stderr)
        sys.exit(1)

    capture = sys.argv[1]
    if not Path(capture).is_file():
        print(f"not a file: {capture}", file=sys.stderr)
        sys.exit(2)

    out, key = anonymize(capture)
    print(f"anonymized -> {out}")
    print(f"key        -> {key}  (chmod 0600, do not share)")
