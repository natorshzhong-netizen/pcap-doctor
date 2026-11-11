"""把解析结果拼成一次完整分析。"""

from __future__ import annotations

from datetime import datetime, timezone

from .detect import detect
from .dns import build_dns_queries
from .flows import build_tcp_flows
from .models import AnalysisResult, PacketView


def analyze_views(views: list[PacketView], path: str = "<memory>") -> AnalysisResult:
    flows = build_tcp_flows(views)
    queries = build_dns_queries(views)
    if views:
        started = datetime.fromtimestamp(views[0].ts, tz=timezone.utc)
        duration = max(0.0, views[-1].ts - views[0].ts)
    else:
        started = None
        duration = 0.0
    result = AnalysisResult(
        path=path,
        packet_count=len(views),
        captured_at=started,
        duration_s=round(duration, 3),
        flows=flows,
        dns=queries,
        bytes_total=sum(item.payload_len for item in views),
    )
    result.findings = detect(result, views)
    return result
