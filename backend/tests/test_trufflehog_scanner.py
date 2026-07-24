"""Tests for TrufflehogScanner: JSON parse, tiering, redaction."""
import json
from scanners.trufflehog_scanner import TrufflehogScanner, _redact_secret


def test_redact_secret_masks_middle():
    r = _redact_secret("AKIAIOSFODNN7EXAMPLE")
    assert r != "AKIAIOSFODNN7EXAMPLE"          # not the raw value
    assert r.startswith("AKIA")                  # keeps a prefix
    assert r.endswith("MPLE")                    # keeps a suffix
    assert "*" in r or "…" in r                  # middle masked


def test_redact_short_secret_fully_masked():
    # short secrets can't safely show prefix+suffix; mask entirely
    r = _redact_secret("abc")
    assert "abc" not in r


def test_parse_verified_secret_is_high_or_critical():
    # trufflehog --json emits one JSON object per finding
    line = json.dumps({
        "DetectorName": "Github",
        "Verified": True,
        "Raw": "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "SourceMetadata": {"Data": {"Filesystem": {"file": "/scan/app.js"}}},
    })
    scanner = TrufflehogScanner()
    findings = scanner._parse_lines([line])
    assert len(findings) == 1
    assert findings[0].severity in ("high", "critical")
    # secret is redacted in evidence
    assert "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" not in findings[0].evidence
    assert "Github" in findings[0].title


def test_parse_unverified_secret_is_low():
    line = json.dumps({
        "DetectorName": "Generic",
        "Verified": False,
        "Raw": "sk-somethingthatlookslikeakey12345",
        "SourceMetadata": {"Data": {"Filesystem": {"file": "/scan/main.js"}}},
    })
    scanner = TrufflehogScanner()
    findings = scanner._parse_lines([line])
    assert len(findings) == 1
    assert findings[0].severity == "low"


def test_parse_aws_verified_is_critical():
    line = json.dumps({
        "DetectorName": "AWS",
        "Verified": True,
        "Raw": "AKIAIOSFODNN7EXAMPLE",
        "SourceMetadata": {"Data": {"Filesystem": {"file": "/scan/config.js"}}},
    })
    scanner = TrufflehogScanner()
    findings = scanner._parse_lines([line])
    assert findings[0].severity == "critical"


def test_parse_skips_malformed_and_non_finding_lines():
    # trufflehog may emit log lines / blanks interleaved with JSON findings
    lines = ["", "not json", '{"level":"info","msg":"scanning"}',
             json.dumps({"DetectorName": "Github", "Verified": False, "Raw": "ghp_x",
                         "SourceMetadata": {"Data": {"Filesystem": {"file": "/scan/a.js"}}}})]
    scanner = TrufflehogScanner()
    findings = scanner._parse_lines(lines)
    # only the one real finding (a line with no DetectorName is not a finding)
    assert len(findings) == 1
