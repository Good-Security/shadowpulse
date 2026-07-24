"""Tests for NaabuScanner JSON parsing and ports_by_host helper."""
from scanners.naabu_scanner import NaabuScanner, ports_by_host
from scanners.base import ServiceArtifact


def test_parse_naabu_jsonl_emits_services():
    # naabu -json emits one JSON object per open port
    lines = [
        '{"ip":"203.0.113.5","port":443,"protocol":"tcp","host":"203.0.113.5"}',
        '{"ip":"203.0.113.5","port":80,"protocol":"tcp","host":"203.0.113.5"}',
    ]
    scanner = NaabuScanner()
    findings, assets, services = scanner._parse_lines(lines)
    ports = sorted(s.port for s in services)
    assert ports == [80, 443]
    assert all(s.proto == "tcp" for s in services)
    assert all(s.host_normalized == "203.0.113.5" for s in services)


def test_parse_naabu_skips_malformed_lines():
    lines = ["not json", "", '{"ip":"203.0.113.5","port":22,"protocol":"tcp"}']
    scanner = NaabuScanner()
    _, _, services = scanner._parse_lines(lines)
    assert [s.port for s in services] == [22]


def test_ports_by_host_groups_and_joins():
    services = [
        ServiceArtifact(host_type="ip", host_value="10.0.0.1", host_normalized="10.0.0.1", port=443, proto="tcp"),
        ServiceArtifact(host_type="ip", host_value="10.0.0.1", host_normalized="10.0.0.1", port=80, proto="tcp"),
        ServiceArtifact(host_type="ip", host_value="10.0.0.2", host_normalized="10.0.0.2", port=8443, proto="tcp"),
    ]
    mapping = ports_by_host(services)
    # ports sorted ascending, comma-joined, no duplicates
    assert mapping["10.0.0.1"] == "80,443"
    assert mapping["10.0.0.2"] == "8443"


def test_ports_by_host_dedups():
    services = [
        ServiceArtifact(host_type="ip", host_value="10.0.0.1", host_normalized="10.0.0.1", port=443, proto="tcp"),
        ServiceArtifact(host_type="ip", host_value="10.0.0.1", host_normalized="10.0.0.1", port=443, proto="tcp"),
    ]
    assert ports_by_host(services)["10.0.0.1"] == "443"
