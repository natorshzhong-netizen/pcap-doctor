"""命令行入口。

python -m pcap_doctor demo --open
python -m pcap_doctor analyze capture.pcap --report reports/capture.html
python -m pcap_doctor capture --seconds 20 --iface "Wi-Fi" --out capture.pcap
"""

from __future__ import annotations

import argparse
import json
import sys
import webbrowser
from dataclasses import asdict
from pathlib import Path

from . import __version__
from .analyze import analyze_views
from .demo import SCENARIOS, write_demo_pcaps
from .load import load_pcap
from .models import SEVERITY_LABELS, AnalysisResult, Severity
from .report import write_report

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DEMO_DIR = ROOT / "demo"
DEFAULT_REPORT_DIR = ROOT / "reports"


def _setup_stdout() -> None:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except AttributeError:
        pass


def _print_summary(result: AnalysisResult, report: Path) -> None:
    print(
        f"\n{Path(result.path).name}：{result.packet_count} 个包 · "
        f"{result.tcp_flows} 条 TCP 流 · {result.dns_queries} 次 DNS · "
        f"{len(result.findings)} 条发现"
    )
    if not result.findings:
        print("  ✓ 未命中任何诊断规则")
    for finding in result.findings:
        label = SEVERITY_LABELS[finding.severity]
        metric = f"（{finding.metric}）" if finding.metric else ""
        print(f"  [{label}] {finding.title}{metric}")
    print(f"  报告：{report}")


def _write_json(result: AnalysisResult, path: str | Path) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(asdict(result), ensure_ascii=False, indent=2, default=str),
        encoding="utf-8",
    )


def cmd_analyze(args: argparse.Namespace) -> int:
    path = Path(args.pcap)
    if not path.exists():
        print(f"✗ 找不到文件：{path}")
        return 1
    try:
        result = analyze_views(load_pcap(path), str(path))
    except Exception as exc:  # noqa: BLE001 - 损坏的 pcap 不应打印堆栈
        print(f"✗ 解析失败：{exc}")
        return 1

    report = write_report(result, args.report)
    if args.json:
        _write_json(result, args.json)
    _print_summary(result, report)
    if args.open:
        webbrowser.open(report.resolve().as_uri())
    if args.fail_on_high:
        high = [item for item in result.findings if item.severity in (Severity.CRITICAL, Severity.HIGH)]
        return 1 if high else 0
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    demo_dir = Path(args.demo_dir)
    report_dir = Path(args.report_dir)
    paths = write_demo_pcaps(demo_dir)
    print(f"已生成 {len(paths)} 个演示 pcap → {demo_dir}")

    results: dict[str, tuple[AnalysisResult, Path]] = {}
    for name, path in paths.items():
        result = analyze_views(load_pcap(path), str(path))
        report = write_report(result, report_dir / f"{name}.html")
        results[name] = (result, report)
        _print_summary(result, report)

    links = "".join(
        f'<li><a href="{path.name}">{name}</a> — {SCENARIOS[name][1]}（{len(result.findings)} 条发现）</li>'
        for name, (result, path) in results.items()
    )
    index = report_dir / "index.html"
    index.write_text(
        "<!doctype html><html lang='zh-CN'><meta charset='utf-8'>"
        "<title>pcap-doctor demo</title>"
        "<style>body{font-family:system-ui,'Microsoft YaHei',sans-serif;max-width:720px;"
        "margin:48px auto;line-height:1.8;color:#0f172a}code{background:#eef2f7;padding:2px 6px;border-radius:5px}</style>"
        "<h1>pcap-doctor · 演示场景</h1><p>每个文件都注入了已知故障，打开报告看归因与证据。</p>"
        f"<ul>{links}</ul>"
        "<p>重新生成：<code>python -m pcap_doctor demo</code></p></html>",
        encoding="utf-8",
    )
    print(f"\n索引：{index}")
    if args.open:
        webbrowser.open((report_dir / "mixed.html").resolve().as_uri())
    return 0


def cmd_capture(args: argparse.Namespace) -> int:
    try:
        from scapy.all import sniff, wrpcap
    except Exception as exc:  # noqa: BLE001
        print(f"✗ 无法加载抓包引擎：{exc}")
        return 1

    print(f"▶ 抓包 {args.seconds}s（接口：{args.iface or '自动'}），Ctrl+C 可提前结束")
    try:
        packets = sniff(iface=args.iface or None, timeout=args.seconds, store=True)
    except Exception as exc:  # noqa: BLE001 - 缺驱动/权限是常见路径
        print(f"✗ 抓包失败：{exc}")
        print("  实时抓包需要安装 Npcap（Wireshark 安装包里勾选 Npcap），并以管理员身份运行。")
        print("  没有驱动也可以先用 `python -m pcap_doctor demo` 跑离线样本。")
        return 1
    if not packets:
        print("✗ 没有抓到数据包")
        return 1
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(out), packets)
    print(f"✓ 已保存 {len(packets)} 个包 → {out}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pcap-doctor",
        description="从 pcap 里定位网络慢/断的根因，并给出可核对的证据。",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    demo = sub.add_parser("demo", help="生成带故障的演示 pcap 并输出报告")
    demo.add_argument("--demo-dir", default=str(DEFAULT_DEMO_DIR))
    demo.add_argument("--report-dir", default=str(DEFAULT_REPORT_DIR))
    demo.add_argument("--open", action="store_true")
    demo.set_defaults(func=cmd_demo)

    analyze = sub.add_parser("analyze", help="分析一个 pcap 文件")
    analyze.add_argument("pcap")
    analyze.add_argument("--report", default=str(DEFAULT_REPORT_DIR / "report.html"))
    analyze.add_argument("--json", default="")
    analyze.add_argument("--open", action="store_true")
    analyze.add_argument("--fail-on-high", action="store_true", help="有高危发现时退出码为 1")
    analyze.set_defaults(func=cmd_analyze)

    capture = sub.add_parser("capture", help="实时抓包（需要 Npcap）")
    capture.add_argument("--seconds", type=int, default=20)
    capture.add_argument("--iface", default="")
    capture.add_argument("--out", default="capture.pcap")
    capture.set_defaults(func=cmd_capture)
    return parser


def main(argv: list[str] | None = None) -> int:
    _setup_stdout()
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        print("\n已中断")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
