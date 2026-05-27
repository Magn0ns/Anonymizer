# Anonymizer

Reversible, format-preserving anonymization of IPv4, IPv6, MAC and L4 port
fields in Wireshark capture files (`.pcap` / `.pcapng`).

[![Python](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## What it does

Given a capture file, the tool produces a second capture where every IPv4,
IPv6, MAC address and L4 port has been replaced with an encrypted value
that *looks like* a normal value of the same type (a valid IPv4 address,
a valid port number in `0..65535`, etc.). The same input always maps to
the same output, so flows stay coherent across packets and over time. A
sidecar key file lets the legitimate operator reverse the process and
recover the original capture exactly.

| Field   | Width    | Domain preserved as           |
|---------|----------|-------------------------------|
| IPv4    | 32 bits  | Valid IPv4 dotted-quad        |
| IPv6    | 120 bits | Valid IPv6, top byte preserved (multicast / link-local / global-unicast scope unchanged) |
| MAC     | 48 bits  | Valid MAC (`xx:xx:xx:xx:xx:xx`) |
| L4 port | 16 bits  | Valid port number (`0..65535`) |

The transformation is a per-field **Feistel network** keyed by an
HKDF-derived sub-key, so output looks indistinguishable from random
across the domain while remaining a true permutation (collision-free,
invertible).

## Quick start

```bash
# install
pip install -e .

# anonymize a capture (key file is auto-generated next to the output)
anonymizer capture.pcapng
# -> capture_anon.pcapng
# -> capture_anon_key.txt   (chmod 0600, do not share)

# reverse the process using the sidecar key
anonymizer capture_anon.pcapng --decrypt
# -> capture_decrypted_<timestamp>.pcapng
```

### Useful flags

```bash
anonymizer capture.pcapng \
    --fields ipv4 ipv6 mac port \   # subset of fields to touch (default: all)
    --threads 8 \                   # worker threads (default: 4)
    --batch-size 2000 \             # packets per batch (default: 1000)
    --log-level DEBUG \
    --log-file run.log
```

Pass an explicit key with `--key <base64>` to use a pre-existing key
instead of the sidecar file (useful for batch jobs).
### Security

- **HKDF-SHA256 sub-key derivation** with domain-separated `info`
  labels (`anonymizer.v1.subkey.ipv4`, `.ipv6`, `.mac`, `.port`).
  Replaces the original `SHA256(master||label)[:16]` truncation, which
  is not a KDF.
- **Key file** is written with `0600` permissions on POSIX, via an
  atomic `tempfile.mkstemp` + `os.replace` so a crash never leaves a
  half-written secret. The file carries an HMAC-SHA256 tag that is
  verified on load with constant-time comparison; tampering or
  corruption is rejected loudly.
- **Atomic output**. The anonymized pcap is written to a temp file
  and renamed into place on success. A crash mid-run never leaves a
  truncated capture with the original filename.

### Architecture

- **Package layout**: `src/anonymizer/` with sub-packages for `core/`,
  `crypto/`, `io/`, `processing/`, `utils/`. See
  [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).
- **Configuration is a dataclass** (`AnonymizerConfig`) injected into
  the orchestrator. No more global tuning knobs.
- **Per-module loggers** (`logging.getLogger(__name__)`); the CLI
  configures the root once and can mirror to a file with `--log-file`.
- **Exception hierarchy** under `AnonymizerError` for a clean
  catch-all at the CLI boundary, with `CryptoError`, `KeyError`,
  `IOError`, `ValidationError` subclasses.
- **Cryptographers** are an ABC + Template-Method family built by a
  `CryptographerRegistry` factory that honours the `--fields` flag,
  so opting out of a field truly skips it instead of just gating
  consumers.
- **Tests** with `pytest` covering Feistel round-trip, prefix
  preservation, determinism, edge values (`0.0.0.0`, `255.255.255.255`,
  `::`, `ff::`, port 0, port 65535).

## Architecture at a glance

```
src/anonymizer/
├── cli.py                   # argument parsing + wiring
├── core/
│   ├── config.py            # AnonymizerConfig, supported field set
│   ├── exceptions.py        # AnonymizerError hierarchy
│   └── logging_setup.py
├── crypto/
│   ├── keys.py              # generate / derive / load / save key material
│   ├── aes_address.py       # Feistel FPE primitive
│   ├── cryptographers.py    # one Cryptographer per field family
│   └── factory.py           # CryptographerRegistry builder
├── io/
│   ├── pcap_writer.py       # atomic_pcap_writer context manager
│   └── pcap_io.py           # thread-safe writer
├── processing/
│   ├── sharded_dict.py      # mapping cache (LRU hot tier + sharded cold tier)
│   ├── packet_transformer.py # scapy layer rewriting + checksum invalidation
│   ├── stats.py             # StatsTracker + ErrorTracker
│   ├── batch_processor.py   # thread pool + retry policy
│   └── orchestrator.py      # main Anonymizer class
└── utils/
    ├── validators.py
    └── paths.py
```

## Security notes

- **The sidecar key file is sensitive material.** Anyone holding it can
  fully de-anonymize the corresponding capture. Treat it like an SSH
  private key — `0600` permissions, never commit it, store it
  separately from the anonymized capture if you intend to share the
  capture.
- **Anonymization is not de-identification.** The mapping is a
  permutation, so an attacker who can guess one address (e.g. a router
  on a known network) trivially learns its mapping and gains traffic
  pattern information. The tool is for sharing captures with people
  who should not see the raw addresses, not for adversarial release.
- **No tweak.** Same key + same address always produces the same
  ciphertext across files. If you need different mappings per capture,
  use a fresh key.

## Development

```bash
# clone, then:
pip install -e ".[dev]"
pytest                # full test suite
ruff check src tests  # lint
mypy                  # type-check
```

## License

[MIT](LICENSE).
