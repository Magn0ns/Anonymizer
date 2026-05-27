# Architecture

## Layered package layout

```
              ┌──────────────────────────────────────────┐
              │                  cli.py                  │   (entry point)
              └────────────┬─────────────────────────────┘
                           │ wires
              ┌────────────▼────────────┐
              │   processing/           │
              │   - orchestrator.py     │   (top-level workflow)
              │   - batch_processor.py  │   (threads + retry policy)
              │   - packet_transformer  │   (scapy layer rewriting)
              │   - sharded_dict.py     │   (mapping cache)
              │   - stats.py            │
              └────┬──────────┬─────────┘
                   │          │
        uses       │          │   uses
              ┌────▼───┐  ┌───▼───┐
              │ crypto │  │  io   │
              │        │  │       │
              │ keys   │  │ pcap  │
              │ aes_   │  │_writer│
              │ address│  │ pcap_ │
              │ crypto │  │_io    │
              │_graph- │  └───┬───┘
              │ ers    │      │
              │ factory│      │
              └────┬───┘      │
                   │          │
              ┌────▼──────────▼──┐
              │      core/       │   (config, exceptions, logging)
              └────┬─────────────┘
                   │
              ┌────▼────┐
              │  utils/ │   (validators, path helpers — pure functions)
              └─────────┘
```

Rules of the layout:

- **Dependencies point inward.** `processing` can import from `crypto`,
  `io`, `core`, `utils`. `crypto` can import from `core`, `utils`.
  Nothing imports from `cli`. Nothing in `core` or `utils` imports
  from a higher layer.
- **No global state.** Configuration (`AnonymizerConfig`) and key
  material (`SubKeys`) are constructed in `cli.main`, passed
  explicitly to the orchestrator, threaded down. The only globals
  are constants (`SUPPORTED_FIELDS`, the Feistel round count).
- **One module = one responsibility.** Splitting `packet_transformer.py`
  from `batch_processor.py` from `orchestrator.py` lets each be
  understood, tested, and changed in isolation.

## Data flow during a run

1. **CLI** parses arguments, configures logging, validates the input
   path. It either loads or generates a master key and derives the
   four sub-keys via HKDF.
2. **Factory** (`crypto/factory.py::build_registry`) builds a
   `CryptographerRegistry` honouring `config.fields` — fields the
   user opted out of map to `None` in the registry.
3. **Anonymizer** (`processing/orchestrator.py`) opens the input pcap
   via Scapy, accumulates packets into a `BatchAccumulator`, and
   hands each completed batch to a `BatchProcessor`.
4. **BatchProcessor** dispatches the batch to a `ThreadPoolExecutor`.
   Each worker calls `PacketTransformer.transform()` on its packet.
   Failed packets are returned for a retry pass; the retry loop
   exits as soon as a pass produces no improvement.
5. **PacketTransformer** walks the Scapy layers, calls the relevant
   cryptographer for each field, mutates the packet, and clears
   length/checksum attributes so Scapy recomputes them on serialize.
6. **Cryptographer** queries the `NetworkShardedDict` cache. On miss
   it calls `AESAddressCipher.encrypt_<field>` (or `decrypt_`) and
   caches the result. Cache lookups stay in the hot LRU tier;
   evictions fall to the cold sharded tier.
7. **Atomic writer** (`io/pcap_writer.py`) buffers output to a temp
   file and `os.replace`s it into the final location on success.

```
              read pcap ──► batch accumulator ──► thread pool ──► transformer
                                                                     │
                                                                     ▼
                                                              cryptographer
                                                                     │
                                                          cache hit ─┴─ cache miss
                                                                          │
                                                                          ▼
                                                                  Feistel(AES)
                                                                          │
                                                                          ▼
                                                                  store + return
              ◄── atomic write ◄── batch out ◄── ...
```

## Concurrency

- Per-batch workers are stateless beyond the shared cryptographers and
  caches. AES contexts are constructed per-call inside the round
  function, not reused across threads.
- `NetworkShardedDict` shards keys by `hash(key) % N` so concurrent
  inserts contend on at most one shard's lock.
- The output writer (`io/pcap_io.py::ThreadSafePcapWriter`) serializes
  writes with a single mutex. The pcap format is not friendly to
  parallel append, and the disk is rarely the bottleneck for our
  packet rates.