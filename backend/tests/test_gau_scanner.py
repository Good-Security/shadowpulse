"""Tests for GauScanner URL parsing."""
from scanners.gau_scanner import GauScanner


def test_parse_emits_url_assets():
    lines = [
        "https://example.com/old/page?a=1",
        "https://example.com/api/v1/users",
        "http://example.com/legacy",
    ]
    scanner = GauScanner()
    assets = scanner._parse_lines(lines, max_urls=500)
    norms = {a.normalized for a in assets}
    assert any("example.com/old/page" in n for n in norms)
    assert all(a.type == "url" for a in assets)


def test_parse_dedups_and_caps():
    lines = ["https://example.com/x"] * 10 + [f"https://example.com/p{i}" for i in range(10)]
    scanner = GauScanner()
    assets = scanner._parse_lines(lines, max_urls=5)
    assert len(assets) <= 5
    # dedup: the repeated /x collapses to one
    norms = [a.normalized for a in assets]
    assert len(norms) == len(set(norms))


def test_parse_skips_blank_and_garbage():
    lines = ["", "   ", "not a url", "https://example.com/ok"]
    scanner = GauScanner()
    assets = scanner._parse_lines(lines, max_urls=500)
    assert any("example.com/ok" in a.normalized for a in assets)
