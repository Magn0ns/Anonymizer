"""
Single-packet anonymization logic.

Separating "transform one packet" from "drive the thread pool" keeps the
crypto logic testable in isolation and lets us swap the transport
(threading, multiprocessing, ...) without touching the per-packet code.

The transformer treats the packet as a tree of layers and walks each
layer once. Layers absent from the packet are skipped silently.

Supported layers
----------------
* Ethernet (``Ether``)            -> src/dst MAC
* IPv4 (``IP``)                   -> src/dst
* IPv6 (``IPv6``)                 -> src/dst
* TCP and UDP (``TCP``, ``UDP``)  -> sport/dport
* ARP (``ARP``)                   -> hwsrc/hwdst (MAC) and psrc/pdst (IP)
"""

from __future__ import annotations

import logging
from typing import Optional, Tuple

from scapy.layers.inet import IP, TCP, UDP  # type: ignore
from scapy.layers.inet6 import IPv6  # type: ignore
from scapy.layers.l2 import ARP, Ether  # type: ignore
from scapy.packet import Packet  # type: ignore

from ..crypto.factory import CryptographerRegistry

logger = logging.getLogger(__name__)


class PacketTransformer:
    """Apply a ``CryptographerRegistry`` to a single scapy packet.

    Always returns ``(modified, packet_or_None)``: a ``False`` result
    means the packet had no targetable fields and the caller can pass
    the original through unchanged (avoiding a needless copy).
    """

    def __init__(self, registry: CryptographerRegistry) -> None:
        self._reg = registry

    def transform(self, packet: Packet) -> Tuple[bool, Optional[Packet]]:
        """Anonymize ``packet`` and return ``(modified, new_packet_or_None)``."""
        try:
            # ``copy`` is shallow per layer in scapy but creates new
            # mutable layer instances, so we can safely reassign fields.
            new_packet = packet.copy()
            modified = False

            modified |= self._anonymize_ether(new_packet)
            modified |= self._anonymize_arp(new_packet)
            modified |= self._anonymize_ip(new_packet)
            modified |= self._anonymize_ipv6(new_packet)
            modified |= self._anonymize_ports(new_packet)

            if not modified:
                return False, None

            # Invalidate scapy's cached lengths/checksums so they're
            # recomputed on write — otherwise our field edits would
            # ship with checksums that no longer match the payload and
            # downstream readers would flag the packet as corrupt.
            self._invalidate_checksums(new_packet)
            return True, new_packet

        except Exception as exc:  # noqa: BLE001 - scapy's exception surface is wide
            logger.error("Packet transform failed: %s", exc)
            return False, None

    # ------------------------------------------------------------- layers --

    def _anonymize_ether(self, packet: Packet) -> bool:
        if self._reg.mac is None or Ether not in packet:
            return False
        eth = packet[Ether]
        new_src = self._reg.mac.process(eth.src)
        new_dst = self._reg.mac.process(eth.dst)
        changed = (new_src != eth.src) or (new_dst != eth.dst)
        if changed:
            eth.src, eth.dst = new_src, new_dst
        return changed

    def _anonymize_arp(self, packet: Packet) -> bool:
        if ARP not in packet:
            return False
        arp = packet[ARP]
        changed = False
        if self._reg.mac is not None:
            for attr in ("hwsrc", "hwdst"):
                old = getattr(arp, attr, None)
                if not old:
                    continue
                new = self._reg.mac.process(old)
                if new != old:
                    setattr(arp, attr, new)
                    changed = True
        if self._reg.ipv4 is not None:
            for attr in ("psrc", "pdst"):
                old = getattr(arp, attr, None)
                if not old:
                    continue
                new = self._reg.ipv4.process(old)
                if new != old:
                    setattr(arp, attr, new)
                    changed = True
        return changed

    def _anonymize_ip(self, packet: Packet) -> bool:
        if self._reg.ipv4 is None or IP not in packet:
            return False
        ip = packet[IP]
        new_src = self._reg.ipv4.process(ip.src)
        new_dst = self._reg.ipv4.process(ip.dst)
        changed = (new_src != ip.src) or (new_dst != ip.dst)
        if changed:
            ip.src, ip.dst = new_src, new_dst
        return changed

    def _anonymize_ipv6(self, packet: Packet) -> bool:
        if self._reg.ipv6 is None or IPv6 not in packet:
            return False
        ip = packet[IPv6]
        new_src = self._reg.ipv6.process(ip.src)
        new_dst = self._reg.ipv6.process(ip.dst)
        changed = (new_src != ip.src) or (new_dst != ip.dst)
        if changed:
            ip.src, ip.dst = new_src, new_dst
        return changed

    def _anonymize_ports(self, packet: Packet) -> bool:
        if self._reg.port is None:
            return False
        changed = False
        for layer_cls in (TCP, UDP):
            if layer_cls not in packet:
                continue
            layer = packet[layer_cls]
            new_sport = self._reg.port.process(int(layer.sport))
            new_dport = self._reg.port.process(int(layer.dport))
            if new_sport != layer.sport or new_dport != layer.dport:
                layer.sport, layer.dport = new_sport, new_dport
                changed = True
        return changed

    @staticmethod
    def _invalidate_checksums(packet: Packet) -> None:
        """Force scapy to recompute checksums and lengths on serialize.

        Without this, edits to addresses or ports leave packets with
        stale checksum fields and tools like Wireshark will flag them
        as "checksum incorrect".
        """
        layer = packet
        while layer:
            for field in ("chksum", "cksum", "len", "plen"):
                if hasattr(layer, field):
                    try:
                        delattr(layer, field)
                    except (AttributeError, TypeError):
                        pass
            layer = layer.payload if layer.payload else None
            if layer.__class__.__name__ == "NoPayload":
                break
