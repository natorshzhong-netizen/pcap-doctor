"""把 pcap 读成与 scapy 解耦的 PacketView，后续逻辑可以单独测试。"""

from __future__ import annotations

from pathlib import Path

from scapy.layers.dns import DNS
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.packet import Raw
from scapy.utils import rdpcap

from .models import DnsView, PacketView


def _dns_view(packet) -> DnsView | None:
    dns = packet.getlayer(DNS)
    if dns is None:
        return None
    qname = ""
    try:
        if dns.qd is not None and len(dns.qd) > 0:
            raw_name = dns.qd[0].qname
            qname = (
                raw_name.decode("utf-8", errors="replace").rstrip(".")
                if isinstance(raw_name, bytes)
                else str(raw_name)
            )
    except (IndexError, AttributeError, TypeError):
        qname = ""
    return DnsView(
        txid=int(dns.id),
        is_response=bool(dns.qr),
        rcode=int(dns.rcode),
        qname=qname,
    )


def packet_views(packets) -> list[PacketView]:
    views: list[PacketView] = []
    for index, packet in enumerate(packets, start=1):
        ip = packet.getlayer(IP) or packet.getlayer(IPv6)
        if ip is None:
            continue
        tcp = packet.getlayer(TCP)
        udp = packet.getlayer(UDP) if tcp is None else None
        if tcp is not None:
            protocol = "tcp"
            sport, dport = int(tcp.sport), int(tcp.dport)
        elif udp is not None:
            protocol = "udp"
            sport, dport = int(udp.sport), int(udp.dport)
        else:
            protocol = "other"
            sport = dport = None

        raw = packet.getlayer(Raw)
        payload_len = len(bytes(raw)) if raw is not None else 0
        views.append(
            PacketView(
                index=index,
                ts=float(packet.time),
                src=str(ip.src),
                dst=str(ip.dst),
                sport=sport,
                dport=dport,
                protocol=protocol,
                tcp_flags=int(tcp.flags) if tcp is not None else 0,
                seq=int(tcp.seq) if tcp is not None else None,
                ack=int(tcp.ack) if tcp is not None else None,
                window=int(tcp.window) if tcp is not None else None,
                payload_len=payload_len,
                dns=_dns_view(packet),
            )
        )
    return views


def load_pcap(path: str | Path) -> list[PacketView]:
    return packet_views(rdpcap(str(path)))
