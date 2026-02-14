"""Scope enforcement for targets.

Validates that scan targets (domains, IPs, URLs) fall within the
allowed scope defined on a Target's scope_json.
"""

from __future__ import annotations

import ipaddress
import fnmatch
from urllib.parse import urlparse

from pydantic import BaseModel, Field


class ScopeConfig(BaseModel):
    root_domain: str
    allowed_domains: list[str] = Field(default_factory=list)
    allowed_cidrs: list[str] = Field(default_factory=list)
    allowed_url_prefixes: list[str] = Field(default_factory=list)
    max_hosts: int = 50
    max_http_targets: int = 200
    max_concurrent_jobs: int = 3


def parse_scope(scope_json: dict | None, root_domain: str) -> ScopeConfig:
    """Build a ScopeConfig from a target's scope_json, applying defaults."""
    if not scope_json:
        scope_json = {}
    defaults = {
        "root_domain": root_domain,
        "allowed_domains": [root_domain, f"*.{root_domain}"],
    }
    merged = {**defaults, **scope_json}
    return ScopeConfig(**merged)


def domain_in_scope(scope: ScopeConfig, domain: str) -> bool:
    """Check if a domain matches any allowed_domains pattern."""
    domain = domain.lower().strip().rstrip(".")
    for pattern in scope.allowed_domains:
        pattern = pattern.lower().strip().rstrip(".")
        if fnmatch.fnmatch(domain, pattern):
            return True
    return False


def ip_in_scope(scope: ScopeConfig, ip_str: str) -> bool:
    """Check if an IP is within any allowed CIDR."""
    if not scope.allowed_cidrs:
        # If no CIDRs specified, allow all IPs (they were discovered from in-scope domains)
        return True
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    for cidr in scope.allowed_cidrs:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            if addr in net:
                return True
        except ValueError:
            continue
    return False


def url_in_scope(scope: ScopeConfig, url: str) -> bool:
    """Check if a URL's host is in scope (domain or IP check)."""
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""
    except Exception:
        return False
    # Check URL prefix allowlist
    if scope.allowed_url_prefixes:
        for prefix in scope.allowed_url_prefixes:
            if url.startswith(prefix):
                return True
    # Fall back to domain/IP check on the host
    try:
        ipaddress.ip_address(host)
        return ip_in_scope(scope, host)
    except ValueError:
        return domain_in_scope(scope, host)


def check_in_scope(scope: ScopeConfig, value: str, type: str) -> bool:
    """Unified scope check. type is 'domain', 'ip', or 'url'."""
    if type == "domain" or type == "subdomain":
        return domain_in_scope(scope, value)
    elif type == "ip":
        return ip_in_scope(scope, value)
    elif type == "url":
        return url_in_scope(scope, value)
    return True
