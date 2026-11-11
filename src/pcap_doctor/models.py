"""分析结果的数据模型。解析层与判定层只交换这些结构，方便单测。"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


SEVERITY_LABELS: dict[Severity, str] = {
    Severity.CRITICAL: "严重",
    Severity.HIGH: "高",
    Severity.MEDIUM: "中",
    Severity.LOW: "低",
    Severity.INFO: "提示",
}


@dataclass
class DnsView:
    txid: int
    is_response: bool
    rcode: int
    qname: str


@dataclass
class PacketView:
    index: int
    ts: float
    src: str
    dst: str
    sport: int | None
    dport: int | None
    protocol: str
    tcp_flags: int = 0
    seq: int | None = None
    ack: int | None = None
    window: int | None = None
    payload_len: int = 0
    dns: DnsView | None = None

    @property
    def syn(self) -> bool:
        return bool(self.tcp_flags & 0x02)

    @property
    def ack_flag(self) -> bool:
        return bool(self.tcp_flags & 0x10)

    @property
    def rst(self) -> bool:
        return bool(self.tcp_flags & 0x04)

    @property
    def fin(self) -> bool:
        return bool(self.tcp_flags & 0x01)


@dataclass
class TcpFlow:
    key: str
    client: str
    server: str
    packets: int = 0
    bytes_total: int = 0
    bytes_client: int = 0
    bytes_server: int = 0
    start: float = 0.0
    end: float = 0.0
    retransmissions: int = 0
    duplicate_acks: int = 0
    out_of_order: int = 0
    zero_window: int = 0
    resets: int = 0
    syns: int = 0
    synacks: int = 0
    handshake_rtt_ms: float | None = None
    refused: bool = False
    first_packet_index: int = 0
    packet_indices: list[int] = field(default_factory=list)
    retransmission_indices: list[int] = field(default_factory=list)
    reset_indices: list[int] = field(default_factory=list)
    zero_window_indices: list[int] = field(default_factory=list)
    duplicate_ack_indices: list[int] = field(default_factory=list)

    @property
    def duration_s(self) -> float:
        return max(0.0, self.end - self.start)

    @property
    def retrans_rate(self) -> float:
        return self.retransmissions / self.packets if self.packets else 0.0


@dataclass
class DnsQuery:
    client: str
    server: str
    qname: str
    query_ts: float
    response_ts: float | None = None
    latency_ms: float | None = None
    rcode: int | None = None
    query_index: int = 0
    response_index: int | None = None

    @property
    def ok(self) -> bool:
        return self.rcode == 0

    @property
    def rcode_label(self) -> str:
        labels = {0: "NOERROR", 2: "SERVFAIL", 3: "NXDOMAIN", 5: "REFUSED"}
        if self.rcode is None:
            return "无响应"
        return labels.get(self.rcode, f"RCODE {self.rcode}")


@dataclass
class Finding:
    code: str
    severity: Severity
    title: str
    detail: str
    evidence: list[str] = field(default_factory=list)
    flow_key: str | None = None
    metric: str | None = None


@dataclass
class AnalysisResult:
    path: str
    packet_count: int
    captured_at: datetime | None
    duration_s: float
    flows: list[TcpFlow] = field(default_factory=list)
    dns: list[DnsQuery] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    bytes_total: int = 0

    @property
    def tcp_flows(self) -> int:
        return len(self.flows)

    @property
    def dns_queries(self) -> int:
        return len(self.dns)

    @property
    def top_severity(self) -> Severity | None:
        order = list(Severity)
        for severity in order:
            if any(item.severity == severity for item in self.findings):
                return severity
        return None
