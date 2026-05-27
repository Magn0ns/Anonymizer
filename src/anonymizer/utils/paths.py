"""
File path conventions used across the project.

Centralizing the naming rules here keeps the input-to-output mapping
predictable and makes it the single place to change if the project's
naming convention evolves.
"""

from __future__ import annotations

import os
import time


_ANON_SUFFIX = "_anon"


def output_path_for(filename: str, *, is_encrypting: bool) -> str:
    """Build the output file path for an encrypt/decrypt operation.

    Encryption mode appends ``_anon`` before the extension; decryption
    mode strips ``_anon`` (when present) and appends a timestamp, so
    repeated runs never silently overwrite each other.
    """
    directory = os.path.dirname(filename)
    base, ext = os.path.splitext(os.path.basename(filename))

    if is_encrypting:
        new_name = f"{base}{_ANON_SUFFIX}{ext}"
    else:
        if base.endswith(_ANON_SUFFIX):
            base = base[: -len(_ANON_SUFFIX)]
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        new_name = f"{base}_decrypted_{timestamp}{ext}"

    return os.path.join(directory, new_name) if directory else new_name


def key_path_for(filename: str) -> str:
    """Return the conventional key-file path for a given capture file."""
    directory = os.path.dirname(filename)
    base, _ = os.path.splitext(os.path.basename(filename))
    # Use the base name without `_anon` so encrypt and decrypt look at the
    # same key file even if the user passes either form.
    if base.endswith(_ANON_SUFFIX):
        base = base[: -len(_ANON_SUFFIX)]
    name = f"{base}{_ANON_SUFFIX}_key.txt"
    return os.path.join(directory, name) if directory else name
