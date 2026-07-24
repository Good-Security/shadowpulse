"""Tests for TlsxScanner JSON parsing."""
from scanners.tlsx_scanner import TlsxScanner


def test_parse_emits_san_subdomain_assets():
    # tlsx -json -san emits cert metadata incl. subject_an (SAN list)
    lines = [
        '{"host":"app.example.com","port":"443","subject_an":["app.example.com","api.example.com"],'
        '"issuer_cn":"R3","tls_version":"tls13","not_after":"2030-01-01T00:00:00Z"}'
    ]
    scanner = TlsxScanner()
    findings, assets = scanner._parse_lines(lines)
    values = {a.normalized for a in assets if a.type == "subdomain"}
    assert "app.example.com" in values
    assert "api.example.com" in values


def test_parse_flags_weak_tls_version():
    lines = [
        '{"host":"old.example.com","port":"443","subject_an":["old.example.com"],'
        '"issuer_cn":"CA","tls_version":"tls10","not_after":"2030-01-01T00:00:00Z"}'
    ]
    scanner = TlsxScanner()
    findings, assets = scanner._parse_lines(lines)
    weak = [f for f in findings if "tls" in f.title.lower() and f.severity == "low"]
    assert weak, "expected a low-severity weak-TLS finding for tls10"


def test_parse_skips_malformed():
    lines = ["garbage", "", '{"host":"h.example.com","port":"443","subject_an":["h.example.com"],"tls_version":"tls13","not_after":"2030-01-01T00:00:00Z"}']
    scanner = TlsxScanner()
    findings, assets = scanner._parse_lines(lines)
    assert any(a.normalized == "h.example.com" for a in assets)
