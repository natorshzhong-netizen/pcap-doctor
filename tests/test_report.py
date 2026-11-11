from __future__ import annotations

from pathlib import Path

from src.pcap_doctor.analyze import analyze_views
from src.pcap_doctor.demo import write_demo_pcaps
from src.pcap_doctor.load import load_pcap
from src.pcap_doctor.report import render_report, write_report


def _mixed_result(tmp_path: Path):
    paths = write_demo_pcaps(tmp_path / "pcaps")
    return analyze_views(load_pcap(paths["mixed"]), str(paths["mixed"]))


def test_report_contains_findings_and_evidence(tmp_path: Path):
    result = _mixed_result(tmp_path)
    html = render_report(result)
    assert "TCP 连接被拒绝" in html
    assert "TCP 重传偏高" in html
    assert "DNS 解析失败" in html
    assert "包 #" in html
    assert "<style>" in html


def test_report_escapes_dynamic_content(tmp_path: Path):
    result = _mixed_result(tmp_path)
    result.findings[0].title = '<img src=x onerror=alert("xss")>'
    html = render_report(result)
    assert '<img src=x onerror=alert("xss")>' not in html
    assert "&lt;img src=x onerror=alert" in html


def test_write_report_creates_file(tmp_path: Path):
    result = _mixed_result(tmp_path)
    target = write_report(result, tmp_path / "out" / "report.html")
    assert target.exists()
    assert target.read_text(encoding="utf-8").startswith("<!doctype html>")
