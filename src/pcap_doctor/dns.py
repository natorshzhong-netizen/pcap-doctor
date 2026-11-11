"""DNS 查询/响应配对与时延统计。"""

from __future__ import annotations

from .models import DnsQuery, PacketView


def build_dns_queries(packets: list[PacketView]) -> list[DnsQuery]:
    pending: dict[tuple[str, int, str], PacketView] = {}
    queries: list[DnsQuery] = []

    for item in packets:
        item_dns = item.dns
        if item_dns is None:
            continue
        if not item_dns.is_response:
            pending[(item.src, item_dns.txid, item_dns.qname)] = item
            continue

        query = pending.pop((item.dst, item_dns.txid, item_dns.qname), None)
        if query is None:
            # 有些响应不带 question 段，退化为按 txid + 客户端匹配
            for key, candidate in list(pending.items()):
                if key[0] == item.dst and key[1] == item_dns.txid:
                    query = candidate
                    pending.pop(key)
                    break
        if query is None:
            continue

        query_dns = query.dns
        queries.append(
            DnsQuery(
                client=query.src,
                server=query.dst,
                qname=(query_dns.qname if query_dns else "") or item_dns.qname,
                query_ts=query.ts,
                response_ts=item.ts,
                latency_ms=round((item.ts - query.ts) * 1000, 2),
                rcode=item_dns.rcode,
                query_index=query.index,
                response_index=item.index,
            )
        )

    for (client, _txid, qname), query in pending.items():
        queries.append(
            DnsQuery(
                client=client,
                server=query.dst,
                qname=qname,
                query_ts=query.ts,
                query_index=query.index,
            )
        )

    return sorted(queries, key=lambda item: item.query_ts)
