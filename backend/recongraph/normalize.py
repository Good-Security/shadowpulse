from __future__ import annotations

import ipaddress
from urllib.parse import urlparse, urlunparse


def is_ip(value: str) -> bool:
    v = (value or "").strip()
    if not v:
        return False
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def normalize_domain(value: str) -> str:
    v = (value or "").strip()
    if not v:
        return ""

    if "://" in v:
        parsed = urlparse(v)
        host = parsed.hostname or ""
    else:
        host = v.split("/")[0]
        # ipv6 might be in brackets
        if host.startswith("[") and "]" in host:
            host = host[1:host.index("]")]
        # drop port for host:port
        if ":" in host and host.count(":") == 1:
            host = host.split(":")[0]

    host = host.strip().rstrip(".").lower()
    return host


def normalize_url(value: str) -> str:
    v = (value or "").strip()
    if not v:
        return ""

    # If the scanner gives us a bare host, interpret as http.
    if "://" not in v:
        v = "http://" + v

    parsed = urlparse(v)
    scheme = (parsed.scheme or "http").lower()
    host = (parsed.hostname or "").lower()
    port = parsed.port

    # Drop default ports for canonicalization.
    if port and ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        port = None

    netloc = host + (f":{port}" if port else "")

    path = parsed.path or "/"
    if path != "/" and path.endswith("/"):
        path = path[:-1]

    # Inventory-oriented canonical URL: drop query/fragment.
    return urlunparse((scheme, netloc, path, "", "", ""))


def guess_asset_type_from_host(host: str) -> str:
    h = normalize_domain(host)
    if is_ip(h):
        return "ip"
    # Keep it simple for now; treat any hostname as "host" (subdomains are a subset).
    return "host"

