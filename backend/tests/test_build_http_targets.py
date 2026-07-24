"""Tests for _build_http_targets: hostname-first HTTP target selection."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from pipeline.run_pipeline import _build_http_targets


def test_hostnames_produce_https_and_http_urls():
    targets = _build_http_targets(hostnames=["app.example.com"], ip_services=[])
    assert "https://app.example.com/" in targets
    assert "http://app.example.com/" in targets


def test_multiple_hostnames_all_included():
    targets = _build_http_targets(
        hostnames=["a.example.com", "b.example.com"], ip_services=[]
    )
    for h in ("a.example.com", "b.example.com"):
        assert f"https://{h}/" in targets


def test_hostnames_deduped():
    targets = _build_http_targets(
        hostnames=["app.example.com", "app.example.com"], ip_services=[]
    )
    assert targets.count("https://app.example.com/") == 1


def test_bare_ip_service_included_when_no_hostname():
    # A ServiceArtifact-like object: has .port, .proto, .host_normalized
    class Svc:
        port = 443
        proto = "tcp"
        host_normalized = "203.0.113.9"

    targets = _build_http_targets(hostnames=[], ip_services=[Svc()])
    assert "https://203.0.113.9/" in targets


def test_no_cdn_edge_ip_url_when_hostname_present():
    # Regression for Bug A: an IP that a hostname resolved to (CDN edge IP)
    # must NOT be probed by IP — the hostname covers it, and Front Door 404s
    # IP-addressed requests.
    class Svc:
        port = 443
        proto = "tcp"
        host_normalized = "150.171.109.73"  # Azure Front Door edge IP

    targets = _build_http_targets(
        hostnames=["app.servicevelocity.ai"],
        ip_services=[Svc()],
        seen_hostnames={"150.171.109.73"},  # this IP was resolved from the hostname
    )
    assert "https://app.servicevelocity.ai/" in targets
    assert "https://150.171.109.73/" not in targets
    assert "https://150.171.109.73:443" not in targets


def test_bare_ip_probed_when_not_resolved_from_hostname():
    # A bare IP that no hostname resolved to must still be probed, even when
    # the run also discovered an unrelated hostname.
    class Svc:
        port = 443
        proto = "tcp"
        host_normalized = "198.51.100.7"  # not in seen_hostnames

    targets = _build_http_targets(
        hostnames=["app.example.com"],
        ip_services=[Svc()],
        seen_hostnames={"203.0.113.1"},  # a DIFFERENT IP was resolved; not this one
    )
    assert "https://app.example.com/" in targets
    assert any("198.51.100.7" in t for t in targets)  # bare IP still probed


def test_empty_inputs_return_empty():
    assert _build_http_targets(hostnames=[], ip_services=[]) == []
