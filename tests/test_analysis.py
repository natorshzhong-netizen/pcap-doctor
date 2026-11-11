from __future__ import annotations

import pytest

from src.pcap_doctor.analyze import analyze_views
from src.pcap_doctor.demo import write_demo_pcaps
from src.pcap_doctor.load import load_pcap
from src.pcap_doctor.models import Severity


@pytest.fixture(scope="module")
def results(tmp_path_factory):
    folder = tmp_path_factory.mktemp("pcaps")
    paths = write_demo_pcaps(folder)
    return {name: analyze_views(load_pcap(path), str(path)) for name, path in paths.items()}


def test_normal_capture_has_no_findings(results):
    assert results["normal"].findings == []
    assert results["normal"].tcp_flows == 2
    assert results["normal"].dns_queries == 1


def test_retransmission_is_counted_and_attributed(results):
    result = results["retransmission"]
    flow = result.flows[0]
    assert flow.retransmissions == 16
    assert flow.retrans_rate > 0.4
    finding = next(item for item in result.findings if item.code == "tcp_retransmission")
    assert finding.severity == Severity.HIGH
    assert "45" in (finding.metric or "")


def test_refused_connections_are_aggregated_into_one_finding(results):
    result = results["connection-refused"]
    refused = [item for item in result.findings if item.code == "tcp_connection_refused"]
    assert len(refused) == 1
    assert "2 条" in (refused[0].metric or "")
    assert len(result.flows) == 2
    assert all(flow.refused for flow in result.flows)


def test_dns_failure_and_latency(results):
    queries = results["dns-failure"].dns
    assert len(queries) == 3
    bad = next(item for item in queries if item.qname == "bad.example")
    slow = next(item for item in queries if item.qname == "slow.example")
    assert bad.rcode == 3
    assert bad.rcode_label == "NXDOMAIN"
    assert slow.latency_ms >= 1000
    codes = {item.code for item in results["dns-failure"].findings}
    assert codes == {"dns_failure", "dns_slow"}


def test_mixed_scenario_hits_expected_codes(results):
    codes = {item.code for item in results["mixed"].findings}
    assert codes == {
        "tcp_connection_refused",
        "tcp_retransmission",
        "dns_failure",
        "dns_slow",
        "tcp_zero_window",
    }
    zero = next(item for item in results["mixed"].findings if item.code == "tcp_zero_window")
    assert zero.evidence
