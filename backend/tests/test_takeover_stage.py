"""Tests for the takeover-target assembly helper."""
from pipeline.run_pipeline import _takeover_targets


def test_includes_resolved_subdomains():
    targets = _takeover_targets(
        subdomains=["app.example.com", "api.example.com"],
        unresolved=[],
    )
    assert "app.example.com" in targets
    assert "api.example.com" in targets


def test_includes_unresolved_subdomains():
    # unresolved is a list of (hostname, reason) tuples from the DNS stage.
    targets = _takeover_targets(
        subdomains=["app.example.com"],
        unresolved=[("dangling.example.com", "NXDOMAIN"), ("www.app.example.com", "NO_ANSWER")],
    )
    # dangling / unresolved subdomains are prime takeover candidates -> must be scanned
    assert "dangling.example.com" in targets
    assert "www.app.example.com" in targets


def test_dedups_across_resolved_and_unresolved():
    targets = _takeover_targets(
        subdomains=["app.example.com"],
        unresolved=[("app.example.com", "NO_ANSWER")],  # same host in both
    )
    assert targets.count("app.example.com") == 1


def test_empty_inputs_return_empty():
    assert _takeover_targets(subdomains=[], unresolved=[]) == []


def test_skips_blank_entries():
    targets = _takeover_targets(
        subdomains=["", "  ", "real.example.com"],
        unresolved=[("", "x"), ("also.example.com", "y")],
    )
    assert "real.example.com" in targets
    assert "also.example.com" in targets
    assert "" not in targets
    assert "  " not in targets
