"""生成带已知故障的合成 pcap，保证 demo 和评测不依赖外部样本。"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw
from scapy.utils import wrpcap

BASE_TS = datetime(2026, 11, 11, 10, 0, tzinfo=timezone.utc).timestamp()

CLIENT = "192.168.1.10"
SERVER = "93.184.216.34"
OTHER = "203.0.113.50"
DNS_SERVER = "223.5.5.5"


def _tcp(
    offset: float,
    src: str,
    sport: int,
    dst: str,
    dport: int,
    flags: str,
    seq: int,
    ack: int = 0,
    payload: bytes = b"",
    window: int = 64240,
):
    packet = IP(src=src, dst=dst) / TCP(
        sport=sport, dport=dport, flags=flags, seq=seq, ack=ack, window=window
    )
    if payload:
        packet = packet / Raw(payload)
    packet.time = BASE_TS + offset
    return packet


def _dns_query(offset: float, txid: int, qname: str, client: str = CLIENT):
    packet = (
        IP(src=client, dst=DNS_SERVER)
        / UDP(sport=53000, dport=53)
        / DNS(id=txid, qr=0, rd=1, qd=DNSQR(qname=qname))
    )
    packet.time = BASE_TS + offset
    return packet


def _dns_response(
    offset: float,
    txid: int,
    qname: str,
    rcode: int = 0,
    client: str = CLIENT,
):
    dns = DNS(id=txid, qr=1, rd=1, ra=1, rcode=rcode, qd=DNSQR(qname=qname))
    if rcode == 0:
        dns.an = [DNSRR(rrname=qname, type="A", ttl=60, rdata="93.184.216.34")]
    packet = IP(src=DNS_SERVER, dst=client) / UDP(sport=53, dport=53000) / dns
    packet.time = BASE_TS + offset
    return packet


def normal_packets():
    return [
        _dns_query(0.000, 1, "example.com"),
        _dns_response(0.018, 1, "example.com"),
        # 主站：一次干净的 HTTP 会话
        _tcp(0.050, CLIENT, 50000, SERVER, 80, "S", 1000),
        _tcp(0.080, SERVER, 80, CLIENT, 50000, "SA", 5000, 1001),
        _tcp(0.081, CLIENT, 50000, SERVER, 80, "A", 1001, 5001),
        _tcp(
            0.090,
            CLIENT,
            50000,
            SERVER,
            80,
            "PA",
            1001,
            5001,
            b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        ),
        _tcp(0.095, SERVER, 80, CLIENT, 50000, "A", 5001, 1045),
        _tcp(
            0.140,
            SERVER,
            80,
            CLIENT,
            50000,
            "PA",
            5001,
            1045,
            b"HTTP/1.1 200 OK\r\nContent-Length: 1200\r\n\r\n" + b"x" * 1200,
        ),
        _tcp(0.145, CLIENT, 50000, SERVER, 80, "A", 1045, 6261),
        _tcp(0.200, CLIENT, 50000, SERVER, 80, "FA", 1045, 6261),
        _tcp(0.202, SERVER, 80, CLIENT, 50000, "FA", 6261, 1046),
        _tcp(0.203, CLIENT, 50000, SERVER, 80, "A", 1046, 6262),
        # 第二段短连接，用于对比
        _tcp(0.300, CLIENT, 50002, OTHER, 443, "S", 7000),
        _tcp(0.330, OTHER, 443, CLIENT, 50002, "SA", 9000, 7001),
        _tcp(0.331, CLIENT, 50002, OTHER, 443, "A", 7001, 9001),
        _tcp(0.340, CLIENT, 50002, OTHER, 443, "PA", 7001, 9001, b"a" * 300),
        _tcp(0.420, OTHER, 443, CLIENT, 50002, "PA", 9001, 7301, b"b" * 700),
        _tcp(0.425, CLIENT, 50002, OTHER, 443, "A", 7301, 9701),
    ]


def retransmission_packets():
    packets = [
        _tcp(0.000, CLIENT, 50010, SERVER, 443, "S", 1000),
        _tcp(0.050, SERVER, 443, CLIENT, 50010, "SA", 5000, 1001),
        _tcp(0.051, CLIENT, 50010, SERVER, 443, "A", 1001, 5001),
    ]
    seq = 1001
    offset = 0.100
    for _ in range(8):
        for repeat in range(3):
            packets.append(
                _tcp(
                    offset + repeat * 0.010,
                    CLIENT,
                    50010,
                    SERVER,
                    443,
                    "PA",
                    seq,
                    5001,
                    b"d" * 300,
                )
            )
        packets.append(_tcp(offset + 0.040, SERVER, 443, CLIENT, 50010, "A", 5001, seq + 300))
        seq += 300
        offset += 0.060
    return packets


def refused_packets():
    return [
        _tcp(0.000, CLIENT, 50100, SERVER, 8080, "S", 1000),
        _tcp(0.008, SERVER, 8080, CLIENT, 50100, "RA", 0, 1001),
        _tcp(0.500, CLIENT, 50101, SERVER, 8080, "S", 2000),
        _tcp(0.507, SERVER, 8080, CLIENT, 50101, "RA", 0, 2001),
    ]


def dns_failure_packets():
    return [
        _dns_query(0.000, 11, "bad.example"),
        _dns_response(0.030, 11, "bad.example", rcode=3),
        _dns_query(0.100, 12, "good.example"),
        _dns_response(0.122, 12, "good.example"),
        _dns_query(0.200, 13, "slow.example"),
        _dns_response(1.400, 13, "slow.example"),
    ]


def mixed_packets():
    packets = refused_packets()
    packets += retransmission_packets()
    packets += dns_failure_packets()
    # 接收端零窗口：应用处理不过来
    packets += [
        _tcp(1.500, CLIENT, 50200, OTHER, 80, "S", 3000),
        _tcp(1.520, OTHER, 80, CLIENT, 50200, "SA", 8000, 3001),
        _tcp(1.521, CLIENT, 50200, OTHER, 80, "A", 3001, 8001),
        _tcp(1.530, CLIENT, 50200, OTHER, 80, "PA", 3001, 8001, b"upload" * 50),
        _tcp(1.540, OTHER, 80, CLIENT, 50200, "A", 8001, 3301, window=0),
        _tcp(1.900, OTHER, 80, CLIENT, 50200, "A", 8001, 3301, window=64240),
    ]
    return packets


SCENARIOS = {
    "normal": (normal_packets, "干净会话：DNS、握手、HTTP 都正常"),
    "retransmission": (retransmission_packets, "同一序号反复发送，制造重传"),
    "connection-refused": (refused_packets, "服务端直接 RST，制造连接拒绝"),
    "dns-failure": (dns_failure_packets, "NXDOMAIN + 一次 1.2 秒的慢解析"),
    "mixed": (mixed_packets, "拒绝 + 重传 + DNS 失败 + 零窗口"),
}


def write_demo_pcaps(out_dir: str | Path) -> dict[str, Path]:
    target = Path(out_dir)
    target.mkdir(parents=True, exist_ok=True)
    paths: dict[str, Path] = {}
    for name, (builder, _description) in SCENARIOS.items():
        path = target / f"{name}.pcap"
        wrpcap(str(path), builder())
        paths[name] = path
    return paths
