"""TCP 五元组归并与每条流的指标计算。"""

from __future__ import annotations

from collections import defaultdict

from .models import PacketView, TcpFlow


def _endpoint(ip: str, port: int | None) -> tuple[str, int]:
    return (ip, int(port or 0))


def _flow_key(a: tuple[str, int], b: tuple[str, int]) -> str:
    return f"{a[0]}:{a[1]} → {b[0]}:{b[1]}"


def analyze_tcp_flow(segments: list[PacketView], key: str) -> TcpFlow:
    syn = next((item for item in segments if item.syn and not item.ack_flag), None)
    if syn is not None:
        client = _endpoint(syn.src, syn.sport)
        server = _endpoint(syn.dst, syn.dport)
    else:
        first = segments[0]
        client = _endpoint(first.src, first.sport)
        server = _endpoint(first.dst, first.dport)

    flow = TcpFlow(
        key=key,
        client=f"{client[0]}:{client[1]}",
        server=f"{server[0]}:{server[1]}",
        start=segments[0].ts,
        end=segments[-1].ts,
        first_packet_index=segments[0].index,
        packet_indices=[item.index for item in segments],
    )

    first_seen: set[tuple[bool, int, int]] = set()
    max_seq: dict[bool, int] = defaultdict(int)
    last_ack: dict[bool, int | None] = {True: None, False: None}
    synack: PacketView | None = None

    for item in segments:
        flow.packets += 1
        flow.bytes_total += item.payload_len
        is_client = item.src == client[0] and int(item.sport or 0) == client[1]
        if is_client:
            flow.bytes_client += item.payload_len
        else:
            flow.bytes_server += item.payload_len
        if item.syn and item.ack_flag and not is_client and synack is None:
            synack = item
        if item.rst:
            flow.resets += 1
            flow.reset_indices.append(item.index)
        if item.syn and not item.ack_flag:
            flow.syns += 1
        if item.syn and item.ack_flag:
            flow.synacks += 1
        if item.window == 0 and not item.rst:
            flow.zero_window += 1
            flow.zero_window_indices.append(item.index)

        if item.payload_len > 0:
            marker = (is_client, int(item.seq or 0), item.payload_len)
            if marker in first_seen:
                flow.retransmissions += 1
                flow.retransmission_indices.append(item.index)
            else:
                first_seen.add(marker)
                seq = int(item.seq or 0)
                if seq < max_seq[is_client]:
                    flow.out_of_order += 1
                max_seq[is_client] = max(max_seq[is_client], seq)

        is_pure_ack = (
            item.payload_len == 0 and item.ack_flag and not item.syn and not item.fin and not item.rst
        )
        if is_pure_ack:
            previous = last_ack[is_client]
            if previous is not None and item.ack == previous:
                flow.duplicate_acks += 1
                flow.duplicate_ack_indices.append(item.index)
            last_ack[is_client] = item.ack

    if syn is not None and synack is not None:
        flow.handshake_rtt_ms = round((synack.ts - syn.ts) * 1000, 2)
    if syn is not None and synack is None:
        # 服务端在握手阶段直接 RST：端口未监听 / 防火墙拒绝
        flow.refused = any(item.rst and item.src == server[0] and item.ts >= syn.ts for item in segments)

    return flow


def build_tcp_flows(packets: list[PacketView]) -> list[TcpFlow]:
    groups: dict[tuple, list[PacketView]] = {}
    ordered_keys: list[tuple] = []
    for item in packets:
        if item.protocol != "tcp":
            continue
        a = _endpoint(item.src, item.sport)
        b = _endpoint(item.dst, item.dport)
        pair = tuple(sorted((a, b), key=lambda value: (value[0], value[1])))
        if pair not in groups:
            groups[pair] = []
            ordered_keys.append(pair)
        groups[pair].append(item)

    flows: list[TcpFlow] = []
    for pair in ordered_keys:
        segments = groups[pair]
        syn = next((item for item in segments if item.syn and not item.ack_flag), None)
        if syn is not None:
            client = _endpoint(syn.src, syn.sport)
            server = _endpoint(syn.dst, syn.dport)
        else:
            client = _endpoint(segments[0].src, segments[0].sport)
            server = _endpoint(segments[0].dst, segments[0].dport)
        flows.append(analyze_tcp_flow(segments, _flow_key(client, server)))
    return flows
