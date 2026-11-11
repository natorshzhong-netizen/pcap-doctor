"""把流量指标翻译成可执行的诊断结论。

规则只依赖确定性指标，输出稳定，才能进评测集、才能解释每个数字怎么来的。
"""

from __future__ import annotations

from .models import AnalysisResult, DnsQuery, Finding, PacketView, Severity, TcpFlow

SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

RETRANS_MIN_COUNT = 3
RETRANS_MIN_RATE = 0.01
DUP_ACK_MIN = 5
DNS_SLOW_MS = 800.0
HANDSHAKE_SLOW_MS = 300.0


def _pkt_note(index: int, ts_map: dict[int, float], base: float) -> str:
    ts = ts_map.get(index)
    if ts is None:
        return f"包 #{index}"
    return f"包 #{index}（+{ts - base:.2f}s）"


def _flow_evidence(flow: TcpFlow, views: list[PacketView], indices: list[int]) -> list[str]:
    ts_map = {item.index: item.ts for item in views}
    base = views[0].ts if views else 0.0
    picks = indices[:4] or flow.packet_indices[:4]
    notes = [_pkt_note(index, ts_map, base) for index in picks]
    return [f"流：{flow.key}", *notes]


def _dns_evidence(query: DnsQuery, views: list[PacketView]) -> str:
    ts_map = {item.index: item.ts for item in views}
    base = views[0].ts if views else 0.0
    parts = [f"{query.qname or '(无 qname)'} → {query.rcode_label}"]
    if query.latency_ms is not None:
        parts.append(f"{query.latency_ms:.0f} ms")
    parts.append(_pkt_note(query.query_index, ts_map, base))
    if query.response_index is not None:
        parts.append(_pkt_note(query.response_index, ts_map, base))
    return " · ".join(parts)


def detect(result: AnalysisResult, views: list[PacketView]) -> list[Finding]:
    findings: list[Finding] = []

    refused = [flow for flow in result.flows if flow.refused]
    if refused:
        evidence: list[str] = []
        for flow in refused[:3]:
            evidence.extend(_flow_evidence(flow, views, flow.reset_indices))
        findings.append(
            Finding(
                code="tcp_connection_refused",
                severity=Severity.HIGH,
                title="TCP 连接被拒绝",
                detail=(
                    "客户端发出 SYN 后，服务端直接返回 RST，没有完成三次握手。"
                    "通常是端口未监听、服务未启动，或被防火墙/安全组拒绝。"
                ),
                evidence=evidence,
                metric=f"{len(refused)} 条连接被拒绝",
            )
        )

    for flow in result.flows:
        if flow.resets > 0 and not flow.refused:
            findings.append(
                Finding(
                    code="tcp_reset",
                    severity=Severity.MEDIUM,
                    title="连接被中途重置",
                    detail="TCP 连接建立后被 RST 断开，常见于服务端超时、进程崩溃或中间设备中断。",
                    evidence=_flow_evidence(flow, views, flow.reset_indices),
                    flow_key=flow.key,
                    metric=f"{flow.resets} 次 RST",
                )
            )

        if flow.retransmissions >= RETRANS_MIN_COUNT and flow.retrans_rate >= RETRANS_MIN_RATE:
            severity = (
                Severity.HIGH if flow.retransmissions >= 10 or flow.retrans_rate >= 0.05 else Severity.MEDIUM
            )
            findings.append(
                Finding(
                    code="tcp_retransmission",
                    severity=severity,
                    title="TCP 重传偏高",
                    detail=(
                        "同一序号的数据被重复发送，说明报文在链路上丢失或迟迟未确认。"
                        "重传会直接拉高响应时间；先看该流两端的丢包/拥塞，再排查中间设备。"
                    ),
                    evidence=_flow_evidence(flow, views, flow.retransmission_indices),
                    flow_key=flow.key,
                    metric=(
                        f"重传 {flow.retransmissions} 次，占 {flow.retrans_rate * 100:.1f}%，"
                        f"乱序 {flow.out_of_order} 次"
                    ),
                )
            )

        if flow.zero_window > 0:
            findings.append(
                Finding(
                    code="tcp_zero_window",
                    severity=Severity.MEDIUM,
                    title="接收窗口为 0",
                    detail="接收方缓冲区已满，发送方被迫停等；通常意味着下游应用处理太慢。",
                    evidence=_flow_evidence(flow, views, flow.zero_window_indices),
                    flow_key=flow.key,
                    metric=f"{flow.zero_window} 个零窗口报文",
                )
            )

        if flow.duplicate_acks >= DUP_ACK_MIN:
            findings.append(
                Finding(
                    code="tcp_duplicate_ack",
                    severity=Severity.MEDIUM,
                    title="连续重复 ACK",
                    detail="接收方反复确认同一个序号，通常是丢包或乱序触发的快速重传信号。",
                    evidence=_flow_evidence(flow, views, flow.duplicate_ack_indices),
                    flow_key=flow.key,
                    metric=f"{flow.duplicate_acks} 个重复 ACK",
                )
            )

        if flow.handshake_rtt_ms is not None and flow.handshake_rtt_ms >= HANDSHAKE_SLOW_MS:
            findings.append(
                Finding(
                    code="tcp_slow_handshake",
                    severity=Severity.LOW,
                    title="TCP 握手偏慢",
                    detail=(
                        f"SYN → SYN-ACK 用了 {flow.handshake_rtt_ms:.0f} ms。"
                        "握手就慢通常说明 RTT 高或服务端 accept 队列忙，不是应用逻辑问题。"
                    ),
                    evidence=_flow_evidence(flow, views, flow.packet_indices[:3]),
                    flow_key=flow.key,
                    metric=f"握手 RTT {flow.handshake_rtt_ms:.0f} ms",
                )
            )

    failed = [item for item in result.dns if item.rcode not in (None, 0)]
    if failed:
        ratio = len(failed) / len(result.dns) if result.dns else 0.0
        severity = (
            Severity.HIGH if any(item.rcode == 2 for item in failed) or ratio >= 0.5 else Severity.MEDIUM
        )
        findings.append(
            Finding(
                code="dns_failure",
                severity=severity,
                title="DNS 解析失败",
                detail=(
                    "域名解析返回 NXDOMAIN/SERVFAIL 等错误。应用侧通常表现为「打不开」「时好时坏」，"
                    "但 TCP 层根本不会发起连接。"
                ),
                evidence=[_dns_evidence(item, views) for item in failed[:5]],
                metric=f"{len(failed)}/{len(result.dns)} 次解析失败",
            )
        )

    unanswered = [item for item in result.dns if item.rcode is None]
    if unanswered:
        findings.append(
            Finding(
                code="dns_unanswered",
                severity=Severity.MEDIUM,
                title="DNS 查询没有响应",
                detail="抓包窗口内只看到查询、没看到响应，可能是 DNS 服务器不可达或抓包开始得太晚。",
                evidence=[_dns_evidence(item, views) for item in unanswered[:5]],
                metric=f"{len(unanswered)} 次查询无响应",
            )
        )

    slow_dns = [item for item in result.dns if item.latency_ms is not None and item.latency_ms >= DNS_SLOW_MS]
    if slow_dns:
        worst = max(slow_dns, key=lambda item: item.latency_ms or 0)
        findings.append(
            Finding(
                code="dns_slow",
                severity=Severity.MEDIUM,
                title="DNS 解析偏慢",
                detail=(
                    f"最慢一次解析耗时 {worst.latency_ms:.0f} ms。首屏慢、接口还没发出时，先看 DNS 时延。"
                ),
                evidence=[_dns_evidence(item, views) for item in slow_dns[:5]],
                metric=f"{len(slow_dns)} 次超过 {DNS_SLOW_MS:.0f} ms",
            )
        )

    if result.bytes_total > 20_000 and result.flows:
        sent: dict[str, int] = {}
        for flow in result.flows:
            sent[flow.client] = sent.get(flow.client, 0) + flow.bytes_client
            sent[flow.server] = sent.get(flow.server, 0) + flow.bytes_server
        if len(sent) >= 2:
            host, volume = max(sent.items(), key=lambda item: item[1])
            share = volume / result.bytes_total
            if share >= 0.85:
                findings.append(
                    Finding(
                        code="top_talker",
                        severity=Severity.INFO,
                        title="单一主机占用大部分流量",
                        detail="流量集中在一个端点，其他会话可能被它挤占带宽。",
                        evidence=[f"{host} 发送 {volume} 字节，占 {share * 100:.0f}%"],
                        metric=f"{share * 100:.0f}% 流量",
                    )
                )

    findings.sort(key=lambda item: (SEVERITY_ORDER[item.severity], item.code, item.flow_key or ""))
    return findings
