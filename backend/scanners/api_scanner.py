import asyncio
import json
import uuid
from datetime import datetime

import httpx

from scanners.base import BaseScanner, ScanResult, FindingResult, AssetArtifact, EdgeArtifact
from recongraph.normalize import normalize_url, normalize_domain, guess_asset_type_from_host

# Common soft-404 body indicators (lowercase)
SOFT_404_KEYWORDS = [
    "page not found", "not found", "404", "does not exist",
    "doesn't exist", "no longer available", "page you requested",
    "could not be found", "cannot be found", "isn't available",
    "page is missing", "nothing here", "page has moved",
]


class ApiScanner(BaseScanner):
    """Custom API security scanner — tests common API vulnerabilities."""

    name = "api"
    binary = "curl"  # Uses httpx in Python, but curl for availability check

    async def run(self, target: str, config: dict | None = None, stream_callback=None) -> ScanResult:
        config = config or {}
        endpoints = config.get("endpoints", [])
        base_url = target.rstrip("/")
        self._stream = stream_callback

        result = ScanResult(
            scanner=self.name,
            target=target,
            started_at=datetime.utcnow(),
        )

        # ReconGraph artifacts: the base URL is an asset; connect host -> url.
        url_norm = normalize_url(base_url)
        if url_norm:
            result.assets.append(AssetArtifact(type="url", value=base_url, normalized=url_norm))
            host_norm = normalize_domain(base_url)
            if host_norm:
                host_type = guess_asset_type_from_host(host_norm)
                result.assets.append(AssetArtifact(type=host_type, value=host_norm, normalized=host_norm))
                result.edges.append(EdgeArtifact(
                    from_type=host_type,
                    from_value=host_norm,
                    from_normalized=host_norm,
                    to_type="url",
                    to_value=base_url,
                    to_normalized=url_norm,
                    rel_type="serves",
                ))

        # If no endpoints specified, try common API paths
        if not endpoints:
            endpoints = [
                "/", "/api", "/api/v1", "/api/v2",
                "/health", "/status", "/docs", "/swagger.json",
                "/openapi.json", "/.env", "/graphql",
                "/api/users", "/api/admin", "/robots.txt",
                "/sitemap.xml", "/.well-known/security.txt",
            ]

        try:
            # Run checks sequentially so output streams in order
            await self._emit(f"[api] Checking security headers on {base_url}")
            await self._check_security_headers(base_url, result)
            await self._emit(f"[api] Checking CORS configuration")
            await self._check_cors(base_url, result)
            await self._emit(f"[api] Probing {len(endpoints)} endpoints")
            await self._check_endpoints(base_url, endpoints, result)
            await self._emit(f"[api] Testing HTTP methods")
            await self._check_http_methods(base_url, result)
            result.status = "completed"
        except Exception as e:
            result.status = "failed"
            result.error = str(e)

        result.completed_at = datetime.utcnow()
        return result

    async def _emit(self, line: str):
        if self._stream:
            await self._stream(line)

    async def _check_security_headers(self, base_url: str, result: ScanResult):
        """Check for missing security headers."""
        required_headers = {
            "Strict-Transport-Security": {
                "severity": "high",
                "description": "The Strict-Transport-Security (HSTS) header is missing. Without it, browsers allow connections over unencrypted HTTP.",
                "impact": "Attackers on the same network (coffee shop WiFi, corporate LAN) can intercept and modify traffic via man-in-the-middle attacks. Login credentials, session tokens, and sensitive data can be stolen in transit. SSL stripping tools like sslstrip automate this trivially.",
                "remediation": "Add the Strict-Transport-Security header to all HTTPS responses.",
                "remediation_example": "# Nginx\nadd_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;\n\n# Express.js\napp.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true, preload: true }));",
            },
            "X-Content-Type-Options": {
                "severity": "medium",
                "description": "The X-Content-Type-Options header is missing. Browsers may MIME-sniff the response and interpret content differently than intended.",
                "impact": "An attacker can upload a file disguised as an image that actually contains JavaScript. Without this header, the browser may execute it as a script, leading to cross-site scripting (XSS) and data theft.",
                "remediation": "Add X-Content-Type-Options: nosniff to all responses.",
                "remediation_example": "# Nginx\nadd_header X-Content-Type-Options \"nosniff\" always;\n\n# Express.js\napp.use(helmet.noSniff());",
            },
            "X-Frame-Options": {
                "severity": "medium",
                "description": "The X-Frame-Options header is missing. The page can be embedded in an iframe on any other site.",
                "impact": "Attackers can overlay your application in a transparent iframe on a malicious page. Users think they're clicking buttons on the attacker's site but are actually performing actions in your app — changing passwords, making purchases, or approving transactions (clickjacking).",
                "remediation": "Add X-Frame-Options: DENY or SAMEORIGIN to all responses.",
                "remediation_example": "# Nginx\nadd_header X-Frame-Options \"DENY\" always;\n\n# Express.js\napp.use(helmet.frameguard({ action: 'deny' }));\n\n# Django settings.py\nX_FRAME_OPTIONS = 'DENY'",
            },
            "Content-Security-Policy": {
                "severity": "medium",
                "description": "No Content-Security-Policy (CSP) header is set. The browser has no restrictions on what scripts, styles, or resources can load.",
                "impact": "If any XSS vulnerability exists (even a minor one), attackers can inject and execute arbitrary JavaScript — steal cookies, redirect users, capture keystrokes, or exfiltrate data. CSP is the most effective defense-in-depth control against XSS exploitation.",
                "remediation": "Define a Content-Security-Policy that restricts resource loading to trusted sources.",
                "remediation_example": "# Start with a strict policy and relax as needed\nContent-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self';\n\n# Nginx\nadd_header Content-Security-Policy \"default-src 'self'; script-src 'self'\" always;",
            },
            "X-XSS-Protection": {
                "severity": "low",
                "description": "The X-XSS-Protection header is missing. Older browsers' built-in XSS filters won't be explicitly enabled.",
                "impact": "While modern browsers have deprecated this header in favor of CSP, legacy browsers (IE, older Edge) won't activate their XSS auditor. This leaves users on older browsers without an extra layer of reflected XSS protection.",
                "remediation": "Add X-XSS-Protection: 1; mode=block for defense-in-depth.",
                "remediation_example": "# Nginx\nadd_header X-XSS-Protection \"1; mode=block\" always;\n\n# Express.js\napp.use(helmet.xssFilter());",
            },
            "Referrer-Policy": {
                "severity": "low",
                "description": "The Referrer-Policy header is missing. The browser may send the full URL (including query parameters) as the Referer header when navigating to external sites.",
                "impact": "Sensitive data in URLs — session tokens, search queries, user IDs, API keys — can leak to third-party sites through the Referer header. Analytics services, CDNs, and embedded content all receive this information.",
                "remediation": "Set Referrer-Policy to strict-origin-when-cross-origin or no-referrer.",
                "remediation_example": "# Nginx\nadd_header Referrer-Policy \"strict-origin-when-cross-origin\" always;\n\n# HTML meta tag\n<meta name=\"referrer\" content=\"strict-origin-when-cross-origin\">",
            },
        }

        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            try:
                resp = await client.get(base_url)
                for header, info in required_headers.items():
                    if header.lower() not in {k.lower() for k in resp.headers}:
                        result.findings.append(FindingResult(
                            severity=info["severity"],
                            title=f"Missing security header: {header}",
                            description=info["description"],
                            impact=info["impact"],
                            url=base_url,
                            remediation=info["remediation"],
                            remediation_example=info["remediation_example"],
                        ))

                # Check for info leakage in headers
                leaky_headers = {
                    "Server": {
                        "impact": "Knowing the exact web server and version lets attackers search for known vulnerabilities (CVEs) specific to that version. Automated scanners use this to narrow their attack surface immediately.",
                        "remediation_example": "# Nginx — hide version\nserver_tokens off;\n\n# Apache\nServerTokens Prod\nServerSignature Off",
                    },
                    "X-Powered-By": {
                        "impact": "Reveals the backend framework and version (e.g., Express, PHP, ASP.NET). Attackers use this to target framework-specific vulnerabilities and craft payloads tuned to your stack.",
                        "remediation_example": "# Express.js\napp.disable('x-powered-by');\n// or use helmet\napp.use(helmet.hidePoweredBy());\n\n# PHP (php.ini)\nexpose_php = Off",
                    },
                    "X-AspNet-Version": {
                        "impact": "Exposes the exact ASP.NET runtime version. Attackers can look up known deserialization, ViewState, or authentication bypass vulnerabilities for that specific version.",
                        "remediation_example": "<!-- web.config -->\n<httpRuntime enableVersionHeader=\"false\" />\n<customHeaders>\n  <remove name=\"X-AspNet-Version\" />\n</customHeaders>",
                    },
                }
                for h, info in leaky_headers.items():
                    val = resp.headers.get(h)
                    if val:
                        result.findings.append(FindingResult(
                            severity="low",
                            title=f"Information disclosure via {h} header",
                            description=f"The {h} header exposes server technology: {val}",
                            impact=info["impact"],
                            evidence=f"Header value: {val}",
                            url=base_url,
                            remediation=f"Remove or obfuscate the {h} header in production.",
                            remediation_example=info["remediation_example"],
                        ))
            except httpx.RequestError:
                pass

    async def _check_cors(self, base_url: str, result: ScanResult):
        """Check for CORS misconfiguration."""
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            try:
                resp = await client.options(
                    base_url,
                    headers={"Origin": "https://evil.com"}
                )
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                if acao == "*":
                    result.findings.append(FindingResult(
                        severity="high",
                        title="CORS misconfiguration: wildcard origin",
                        description="Access-Control-Allow-Origin is set to *, allowing any website to make authenticated requests to your API.",
                        impact="Any malicious website a user visits can silently make API requests on their behalf. If credentials (cookies/tokens) are included, attackers can read sensitive data, modify account settings, or perform actions as the logged-in user — all from a page the user simply visited.",
                        evidence=f"Access-Control-Allow-Origin: {acao}",
                        url=base_url,
                        remediation="Restrict CORS to specific trusted origins using an allowlist.",
                        remediation_example='# Express.js\nconst cors = require("cors");\napp.use(cors({\n  origin: ["https://app.example.com", "https://admin.example.com"],\n  credentials: true\n}));\n\n# FastAPI\napp.add_middleware(CORSMiddleware, allow_origins=["https://app.example.com"])',
                    ))
                elif "evil.com" in acao:
                    result.findings.append(FindingResult(
                        severity="critical",
                        title="CORS misconfiguration: origin reflection",
                        description="The server blindly reflects any Origin header value back in Access-Control-Allow-Origin. This is worse than a wildcard because it works with credentialed requests.",
                        impact="This is a critical vulnerability. An attacker's website can make fully authenticated cross-origin requests and read the responses. They can exfiltrate user data, API keys, and PII. Combined with Access-Control-Allow-Credentials: true, this gives complete cross-origin access to your API as any authenticated user.",
                        evidence=f"Sent Origin: https://evil.com, Got ACAO: {acao}",
                        url=base_url,
                        remediation="Never reflect the Origin header. Validate against a strict allowlist of trusted domains.",
                        remediation_example='# Python / FastAPI — validate against allowlist\nALLOWED_ORIGINS = {"https://app.example.com", "https://admin.example.com"}\n\n@app.middleware("http")\nasync def cors_middleware(request, call_next):\n    origin = request.headers.get("origin")\n    response = await call_next(request)\n    if origin in ALLOWED_ORIGINS:\n        response.headers["Access-Control-Allow-Origin"] = origin\n    return response',
                    ))
            except httpx.RequestError:
                pass

    async def _check_endpoints(self, base_url: str, endpoints: list[str], result: ScanResult):
        """Probe endpoints for information disclosure."""
        async with httpx.AsyncClient(verify=False, timeout=10, follow_redirects=True) as client:
            # --- Soft-404 calibration ---
            # Fetch a random nonexistent path to fingerprint the custom 404 page
            calibration_path = f"/shadowpulse_calibration_{uuid.uuid4().hex[:8]}"
            baseline_body = ""
            baseline_length = 0
            try:
                cal_resp = await client.get(f"{base_url}{calibration_path}")
                if cal_resp.status_code == 200:
                    baseline_body = cal_resp.text
                    baseline_length = len(baseline_body)
                    await self._emit(f"[api] Soft-404 detected: site returns 200 ({baseline_length} bytes) for unknown paths")
            except httpx.RequestError:
                pass

            for endpoint in endpoints:
                url = f"{base_url}{endpoint}"
                try:
                    resp = await client.get(url)
                    if resp.status_code == 200:
                        content = resp.text[:500]

                        # Skip soft-404 responses
                        if self._is_soft_404(resp.text, baseline_body, baseline_length):
                            continue

                        if endpoint in ["/.env", "/config", "/debug"]:
                            result.findings.append(FindingResult(
                                severity="critical",
                                title=f"Sensitive file accessible: {endpoint}",
                                description=f"The file at {endpoint} is publicly accessible and returned 200 OK. This file typically contains database credentials, API keys, and other secrets.",
                                impact="Attackers can directly read your database passwords, API keys, encryption secrets, and third-party service credentials. This is often a complete compromise — they can access your database, impersonate your services, and pivot to internal systems. Automated scanners constantly probe for these files.",
                                evidence=content[:200],
                                url=url,
                                remediation=f"Block access to {endpoint} at the web server level and rotate all exposed credentials immediately.",
                                remediation_example=f"# Nginx — block dotfiles\nlocation ~ /\\. {{\n    deny all;\n    return 404;\n}}\n\n# Apache .htaccess\n<FilesMatch \"^\\.\">\n    Require all denied\n</FilesMatch>\n\n# IMPORTANT: Rotate all credentials that were in {endpoint}",
                            ))
                        elif endpoint in ["/swagger.json", "/openapi.json", "/docs", "/graphql"]:
                            result.findings.append(FindingResult(
                                severity="medium",
                                title=f"API documentation exposed: {endpoint}",
                                description=f"API documentation at {endpoint} is publicly accessible, revealing all endpoints, parameters, data models, and authentication schemes.",
                                impact="Attackers get a complete blueprint of your API — every endpoint, expected parameters, data types, and authentication methods. This dramatically speeds up targeted attacks by eliminating guesswork. They can identify admin endpoints, unprotected routes, and parameter injection points.",
                                url=url,
                                remediation="Restrict API documentation to authenticated/internal users only.",
                                remediation_example="# FastAPI — disable docs in production\napp = FastAPI(\n    docs_url=None if PRODUCTION else \"/docs\",\n    redoc_url=None if PRODUCTION else \"/redoc\",\n    openapi_url=None if PRODUCTION else \"/openapi.json\"\n)\n\n# Nginx — restrict to internal IPs\nlocation /docs {\n    allow 10.0.0.0/8;\n    deny all;\n}",
                            ))
                        elif endpoint in ["/api/admin"]:
                            result.findings.append(FindingResult(
                                severity="high",
                                title=f"Admin endpoint accessible: {endpoint}",
                                description=f"The admin endpoint {endpoint} returned 200 without requiring authentication. Admin interfaces should never be publicly accessible.",
                                impact="Unauthenticated access to admin functionality can allow attackers to create admin accounts, modify application settings, access all user data, or completely take over the application. Even if the endpoint returns limited data now, it indicates broken access control.",
                                url=url,
                                remediation="Require authentication and admin-role authorization on all admin endpoints.",
                                remediation_example='# FastAPI with dependency injection\n@router.get("/api/admin")\nasync def admin_panel(user: User = Depends(get_current_admin_user)):\n    ...\n\n# Express.js middleware\nrouter.use("/api/admin", requireAuth, requireRole("admin"));',
                            ))
                except httpx.RequestError:
                    continue

    @staticmethod
    def _is_soft_404(body: str, baseline_body: str, baseline_length: int) -> bool:
        """Detect soft-404 responses by comparing against the calibration baseline."""
        if not baseline_body:
            # No baseline — fall back to keyword detection only
            body_lower = body.lower()
            return any(kw in body_lower for kw in SOFT_404_KEYWORDS)

        # Size similarity check: if within 15% of baseline, likely the same page
        body_length = len(body)
        tolerance = max(50, baseline_length * 0.15)
        if abs(body_length - baseline_length) < tolerance:
            return True

        # Keyword fallback for pages with dynamic content that changes size
        body_lower = body.lower()
        return any(kw in body_lower for kw in SOFT_404_KEYWORDS)

    async def _check_http_methods(self, base_url: str, result: ScanResult):
        """Check for dangerous HTTP methods."""
        method_info = {
            "PUT": {
                "impact": "The PUT method can allow attackers to upload or overwrite files on the server. If the server processes PUT requests without authentication, attackers could replace application files, upload web shells, or modify critical configuration.",
                "remediation_example": "# Nginx — restrict methods\nif ($request_method !~ ^(GET|POST|HEAD)$) {\n    return 405;\n}",
            },
            "DELETE": {
                "impact": "The DELETE method could allow attackers to remove resources from the server without authorization. This can lead to data loss, denial of service, or disruption of application functionality.",
                "remediation_example": "# Express.js — only allow on specific routes\napp.delete('/api/resource/:id', requireAuth, deleteHandler);\n// Don't allow DELETE on the root or wildcard routes",
            },
            "TRACE": {
                "impact": "TRACE echoes back the entire HTTP request including headers. Attackers can use Cross-Site Tracing (XST) to steal HttpOnly cookies and authentication tokens that are normally protected from JavaScript access.",
                "remediation_example": "# Apache\nTraceEnable Off\n\n# Nginx (already disabled by default)\n# Verify: curl -X TRACE your-site.com",
            },
            "CONNECT": {
                "impact": "The CONNECT method can turn your server into an open proxy. Attackers can tunnel arbitrary TCP connections through it to access internal services, bypass firewalls, or mask the origin of malicious traffic.",
                "remediation_example": "# Nginx — explicitly deny\nif ($request_method = CONNECT) {\n    return 405;\n}\n\n# Most web servers block this by default — if it's responding, check your proxy configuration.",
            },
        }
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            for method, info in method_info.items():
                try:
                    resp = await client.request(method, base_url)
                    if resp.status_code not in [405, 501, 403, 404]:
                        result.findings.append(FindingResult(
                            severity="medium",
                            title=f"Potentially dangerous HTTP method allowed: {method}",
                            description=f"The server responded with {resp.status_code} to a {method} request instead of rejecting it (405/403). This indicates the method may be processed.",
                            impact=info["impact"],
                            evidence=f"{method} {base_url} → HTTP {resp.status_code}",
                            url=base_url,
                            remediation=f"Disable the {method} HTTP method unless explicitly needed for your application.",
                            remediation_example=info["remediation_example"],
                        ))
                except httpx.RequestError:
                    continue
