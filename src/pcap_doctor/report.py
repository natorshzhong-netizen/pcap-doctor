"""自包含 HTML 诊断报告：结论在前，证据在后。"""

from __future__ import annotations

import html
from pathlib import Path

from .models import (
    SEVERITY_LABELS,
    AnalysisResult,
    DnsQuery,
    Finding,
    Severity,
    TcpFlow,
)

SEVERITY_CLASS = {
    Severity.CRITICAL: "critical",
    Severity.HIGH: "high",
    Severity.MEDIUM: "medium",
    Severity.LOW: "low",
    Severity.INFO: "info",
}
SEVERITY_ICON = {
    Severity.CRITICAL: "!",
    Severity.HIGH: "!",
    Severity.MEDIUM: "▲",
    Severity.LOW: "i",
    Severity.INFO: "i",
}


def _e(value: object) -> str:
    return html.escape(str(value), quote=True)


def _ms(value: float | None) -> str:
    if value is None:
        return "—"
    return f"{value:.0f} ms"


def _bytes(value: int) -> str:
    if value >= 1024 * 1024:
        return f"{value / 1024 / 1024:.1f} MB"
    if value >= 1024:
        return f"{value / 1024:.1f} KB"
    return f"{value} B"


def _finding_card(finding: Finding) -> str:
    severity = SEVERITY_CLASS[finding.severity]
    label = SEVERITY_LABELS[finding.severity]
    evidence = "".join(f"<li>{_e(item)}</li>" for item in finding.evidence)
    metric = f'<span class="metric">{_e(finding.metric)}</span>' if finding.metric else ""
    return f"""
    <article class="finding {severity}">
      <div class="finding-head">
        <span class="sev {severity}"><span aria-hidden="true">{SEVERITY_ICON[finding.severity]}</span>{_e(label)}</span>
        <h3>{_e(finding.title)}</h3>
        {metric}
      </div>
      <p>{_e(finding.detail)}</p>
      <details>
        <summary>证据（{len(finding.evidence)} 条）</summary>
        <ul>{evidence}</ul>
      </details>
    </article>
    """


def _flow_rows(flows: list[TcpFlow]) -> str:
    rows = []
    for flow in sorted(flows, key=lambda item: item.bytes_total, reverse=True):
        warn = ""
        if flow.refused:
            warn = '<span class="tag">RST</span>'
        elif flow.retransmissions:
            warn = f'<span class="tag warn">重传 {flow.retransmissions}</span>'
        rows.append(
            f"""<tr>
              <td class="mono">{_e(flow.client)} → {_e(flow.server)}</td>
              <td>{flow.packets}</td>
              <td>{_bytes(flow.bytes_total)}</td>
              <td>{flow.retransmissions}</td>
              <td>{_ms(flow.handshake_rtt_ms)}</td>
              <td>{flow.duration_s:.2f}s {warn}</td>
            </tr>"""
        )
    return "".join(rows)


def _dns_rows(queries: list[DnsQuery]) -> str:
    rows = []
    for query in queries:
        ok = query.rcode == 0
        cls = "ok" if ok else "bad"
        rows.append(
            f"""<tr>
              <td class="mono">{_e(query.qname or "—")}</td>
              <td class="mono">{_e(query.client)}</td>
              <td>{_ms(query.latency_ms)}</td>
              <td><span class="rcode {cls}">{_e(query.rcode_label)}</span></td>
            </tr>"""
        )
    return "".join(rows)


def _top_bars(flows: list[TcpFlow]) -> str:
    top = [
        flow
        for flow in sorted(flows, key=lambda item: item.bytes_total, reverse=True)
        if flow.bytes_total > 0
    ][:5]
    if not top:
        return '<p class="empty">没有带载荷的 TCP 流量。</p>'
    maximum = max(flow.bytes_total for flow in top) or 1
    rows = []
    for flow in top:
        width = max(3.0, flow.bytes_total / maximum * 100)
        label = f"{flow.client} → {flow.server}"
        rows.append(
            f"""<div class="bar-row">
              <span class="bar-label" title="{_e(label)}">{_e(label)}</span>
              <div class="bar-track"><div class="bar-fill" style="width:{width:.1f}%"></div></div>
              <span class="bar-value">{_bytes(flow.bytes_total)}</span>
            </div>"""
        )
    return f'<div class="bars">{"".join(rows)}</div>'


def render_report(result: AnalysisResult, title: str = "pcap-doctor 诊断报告") -> str:
    high = sum(1 for item in result.findings if item.severity in (Severity.CRITICAL, Severity.HIGH))
    if result.findings:
        headline = f"{len(result.findings)} 条发现"
        subline = f"其中 {high} 条需要优先处理" if high else "没有高危项，但有可优化的地方"
        hero_class = "bad" if high else "warn"
    else:
        headline = "未发现异常"
        subline = "TCP 重传、握手 RTT、DNS 与连接错误都在阈值内"
        hero_class = "good"

    captured = result.captured_at.astimezone().strftime("%Y-%m-%d %H:%M:%S") if result.captured_at else "—"
    findings = (
        "".join(_finding_card(item) for item in result.findings)
        if result.findings
        else '<p class="empty">这段抓包里没有命中任何诊断规则。可以换一段 pcap，或用 demo 注入故障看效果。</p>'
    )
    dns_section = (
        f"""
    <section class="panel">
      <div class="panel-head"><h2>DNS 解析</h2><span class="panel-note">{len(result.dns)} 次查询</span></div>
      <table>
        <thead><tr><th>域名</th><th>客户端</th><th>时延</th><th>结果</th></tr></thead>
        <tbody>{_dns_rows(result.dns)}</tbody>
      </table>
    </section>"""
        if result.dns
        else ""
    )

    return f"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>{_e(title)} · {_e(Path(result.path).name)}</title>
<style>
:root {{
  color-scheme: light;
  --page: #f7f8fa;
  --surface: #ffffff;
  --ink: #0f172a;
  --ink-2: #475569;
  --muted: #94a3b8;
  --line: #e2e8f0;
  --accent: #2a78d6;
  --accent-soft: #eaf2fd;
  --bad: #d03b3b;
  --bad-soft: #fdecec;
  --warn: #fab219;
  --warn-soft: #fff6df;
  --good: #0ca30c;
  --good-soft: #eaf7ea;
  --radius: 14px;
}}
@media (prefers-color-scheme: dark) {{
  :root {{
    color-scheme: dark;
    --page: #0d0d0d;
    --surface: #1a1a19;
    --ink: #f0efec;
    --ink-2: #c3c2b7;
    --muted: #898781;
    --line: #2c2c2a;
    --accent: #3987e5;
    --accent-soft: #17273a;
    --bad: #e66767;
    --bad-soft: #2a1515;
    --warn-soft: #2b2110;
    --good: #0ca30c;
    --good-soft: #142614;
  }}
}}
* {{ box-sizing: border-box; }}
body {{
  margin: 0; background: var(--page); color: var(--ink);
  font-family: system-ui, -apple-system, "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif;
  font-size: 14px; line-height: 1.65; -webkit-font-smoothing: antialiased;
}}
.wrap {{ max-width: 1080px; margin: 0 auto; padding: 32px 24px 56px; }}
header {{ display: flex; align-items: baseline; justify-content: space-between; gap: 16px; margin-bottom: 26px; }}
.brand strong {{ font-size: 18px; letter-spacing: -0.02em; }}
.brand span {{ margin-left: 10px; color: var(--muted); font-size: 12px; }}
.meta {{ color: var(--muted); font-size: 12px; text-align: right; }}
h1 {{ margin: 0 0 4px; font-size: 34px; letter-spacing: -0.03em; }}
h1.bad {{ color: var(--bad); }}
h1.warn {{ color: var(--ink); }}
h1.good {{ color: var(--good); }}
.sub {{ margin: 0; color: var(--ink-2); }}
.kpis {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; margin: 24px 0; }}
.kpi {{ padding: 14px 16px; border: 1px solid var(--line); border-radius: var(--radius); background: var(--surface); }}
.kpi-label {{ margin: 0; color: var(--muted); font-size: 11.5px; }}
.kpi-value {{ margin: 4px 0 0; font-size: 24px; font-weight: 700; letter-spacing: -0.02em; }}
.panel {{ margin-bottom: 20px; padding: 20px 22px; border: 1px solid var(--line); border-radius: var(--radius); background: var(--surface); }}
.panel-head {{ display: flex; align-items: baseline; justify-content: space-between; gap: 12px; }}
h2 {{ margin: 0 0 12px; font-size: 15px; }}
.panel-note {{ color: var(--muted); font-size: 11.5px; }}
.finding {{ margin-bottom: 12px; padding: 16px 18px; border: 1px solid var(--line); border-left: 4px solid var(--muted); border-radius: 10px; }}
.finding.high, .finding.critical {{ border-left-color: var(--bad); }}
.finding.medium {{ border-left-color: var(--warn); }}
.finding.low {{ border-left-color: var(--accent); }}
.finding-head {{ display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }}
.finding h3 {{ margin: 0; font-size: 15px; }}
.sev {{ display: inline-flex; align-items: center; gap: 5px; padding: 2px 8px; border-radius: 999px; font-size: 11px; font-weight: 700; }}
.sev span {{ display: inline-grid; place-items: center; width: 13px; height: 13px; border-radius: 50%; color: #fff; font-size: 9px; }}
.sev.high, .sev.critical {{ background: var(--bad-soft); color: var(--bad); }}
.sev.high span, .sev.critical span {{ background: var(--bad); }}
.sev.medium {{ background: var(--warn-soft); color: var(--ink); }}
.sev.medium span {{ background: var(--warn); color: #0b0b0b; }}
.sev.low {{ background: var(--accent-soft); color: var(--accent); }}
.sev.low span {{ background: var(--accent); }}
.sev.info {{ background: var(--page); color: var(--ink-2); }}
.sev.info span {{ background: var(--muted); }}
.metric {{ margin-left: auto; color: var(--muted); font-size: 11.5px; }}
.finding p {{ margin: 8px 0 4px; color: var(--ink-2); }}
details summary {{ cursor: pointer; color: var(--accent); font-size: 12px; }}
details ul {{ margin: 6px 0 0; padding-left: 18px; color: var(--muted); font-size: 12px; }}
table {{ width: 100%; border-collapse: collapse; font-size: 12.5px; }}
th {{ padding: 7px 8px; border-bottom: 1px solid var(--line); color: var(--muted); font-size: 11px; text-align: left; font-weight: 600; }}
td {{ padding: 8px; border-bottom: 1px solid var(--line); }}
tr:last-child td {{ border-bottom: 0; }}
.mono {{ font-family: ui-monospace, "Cascadia Code", Consolas, monospace; font-size: 11.5px; }}
.tag {{ display: inline-block; margin-left: 6px; padding: 1px 6px; border-radius: 999px; background: var(--bad-soft); color: var(--bad); font-size: 10px; }}
.tag.warn {{ background: var(--warn-soft); color: var(--ink); }}
.rcode {{ padding: 1px 6px; border-radius: 999px; font-size: 10.5px; }}
.rcode.ok {{ background: var(--good-soft); color: var(--good); }}
.rcode.bad {{ background: var(--bad-soft); color: var(--bad); }}
.bars {{ display: flex; flex-direction: column; gap: 10px; }}
.bar-row {{ display: grid; grid-template-columns: 300px 1fr 70px; gap: 12px; align-items: center; }}
.bar-label {{ overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--ink-2); font-size: 11.5px; text-align: right; }}
.bar-track {{ height: 9px; border-radius: 4px; background: var(--line); overflow: hidden; }}
.bar-fill {{ height: 9px; border-radius: 0 4px 4px 0; background: var(--accent); }}
.bar-value {{ color: var(--ink-2); font-size: 11.5px; font-variant-numeric: tabular-nums; }}
.empty {{ margin: 4px 0; color: var(--muted); font-size: 13px; }}
footer {{ margin-top: 28px; padding-top: 16px; border-top: 1px solid var(--line); color: var(--muted); font-size: 11.5px; }}
@media (max-width: 820px) {{
  .kpis {{ grid-template-columns: 1fr 1fr; }}
  .bar-row {{ grid-template-columns: 150px 1fr 60px; }}
  .meta {{ display: none; }}
}}
@media print {{ body {{ background: #fff; }} .panel, .finding {{ break-inside: avoid; }} }}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div class="brand"><strong>pcap-doctor</strong><span>网络诊断报告</span></div>
    <div class="meta">{_e(Path(result.path).name)}<br />抓包时间 {_e(captured)}</div>
  </header>

  <h1 class="{hero_class}">{_e(headline)}</h1>
  <p class="sub">{_e(subline)} · 分析 {result.packet_count} 个包 / {result.tcp_flows} 条 TCP 流 / {result.dns_queries} 次 DNS</p>

  <section class="kpis">
    <div class="kpi"><p class="kpi-label">数据包</p><p class="kpi-value">{result.packet_count}</p></div>
    <div class="kpi"><p class="kpi-label">TCP 流</p><p class="kpi-value">{result.tcp_flows}</p></div>
    <div class="kpi"><p class="kpi-label">DNS 查询</p><p class="kpi-value">{result.dns_queries}</p></div>
    <div class="kpi"><p class="kpi-label">流量</p><p class="kpi-value">{_bytes(result.bytes_total)}</p></div>
    <div class="kpi"><p class="kpi-label">抓包时长</p><p class="kpi-value">{result.duration_s:.1f}s</p></div>
  </section>

  <section class="panel">
    <div class="panel-head"><h2>诊断结论</h2><span class="panel-note">按严重程度排序</span></div>
    {findings}
  </section>

  <section class="panel">
    <div class="panel-head"><h2>流量最大的会话</h2><span class="panel-note">按载荷字节数</span></div>
    {_top_bars(result.flows)}
  </section>

  <section class="panel">
    <div class="panel-head"><h2>TCP 会话</h2><span class="panel-note">{result.tcp_flows} 条</span></div>
    <table>
      <thead><tr><th>客户端 → 服务端</th><th>包数</th><th>字节</th><th>重传</th><th>握手 RTT</th><th>时长</th></tr></thead>
      <tbody>{_flow_rows(result.flows) if result.flows else '<tr><td colspan="6" class="empty">没有 TCP 流量。</td></tr>'}</tbody>
    </table>
  </section>

  {dns_section}

  <footer>由 pcap-doctor 生成 · 报告为单文件，可直接归档或发给同事 · 阈值与规则见 README</footer>
</div>
</body>
</html>
"""


def write_report(result: AnalysisResult, path: str | Path, title: str | None = None) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render_report(result, title or "pcap-doctor 诊断报告"), encoding="utf-8")
    return target
