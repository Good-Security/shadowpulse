from datetime import datetime

import httpx

from scanners.base import BaseScanner, ScanResult, FindingResult, AssetArtifact, EdgeArtifact
from recongraph.normalize import normalize_url, normalize_domain, guess_asset_type_from_host


class OwaspScanner(BaseScanner):
    """Checks for OWASP Top 10 misconfigurations via HTTP analysis."""

    name = "owasp"
    binary = "curl"

    async def run(self, target: str, config: dict | None = None, stream_callback=None) -> ScanResult:
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

        try:
            async with httpx.AsyncClient(verify=False, timeout=15, follow_redirects=True) as client:
                await self._emit(f"[owasp] GET {base_url}")
                resp = await client.get(base_url)
                await self._emit(f"[owasp] Response: {resp.status_code} ({len(resp.text)} bytes)")

                await self._emit("[owasp] Checking cookie security flags")
                self._check_cookies(resp, result, base_url)
                await self._emit("[owasp] Checking TLS enforcement")
                self._check_tls(base_url, result)
                await self._emit("[owasp] Checking error handling")
                self._check_error_handling(resp, result, base_url)
                await self._emit("[owasp] Checking rate limiting")
                self._check_rate_limiting(resp, result, base_url)

            result.status = "completed"
        except Exception as e:
            result.status = "failed"
            result.error = str(e)

        result.completed_at = datetime.utcnow()
        return result

    async def _emit(self, line: str):
        if self._stream:
            await self._stream(line)

    def _check_cookies(self, resp: httpx.Response, result: ScanResult, url: str):
        """Check cookie security flags."""
        for cookie in resp.cookies.jar:
            issues = []
            impacts = []
            examples = []

            if not cookie.secure:
                issues.append("missing Secure flag")
                impacts.append("Without the Secure flag, this cookie is sent over unencrypted HTTP connections, allowing network attackers to intercept it.")
                examples.append('Set-Cookie: {name}=value; Secure'.format(name=cookie.name))
            if cookie._rest.get("httponly") is None and cookie.name.lower() in [
                "session", "sessionid", "sid", "token", "jwt", "auth"
            ]:
                issues.append("missing HttpOnly flag on sensitive cookie")
                impacts.append("Without HttpOnly, JavaScript (including XSS payloads) can read this cookie via document.cookie, allowing session hijacking.")
                examples.append('Set-Cookie: {name}=value; HttpOnly'.format(name=cookie.name))
            samesite = cookie._rest.get("samesite", "")
            if not samesite or samesite.lower() == "none":
                issues.append("SameSite=None or missing SameSite")
                impacts.append("Without SameSite protection, this cookie is sent with cross-site requests, making CSRF attacks possible.")
                examples.append('Set-Cookie: {name}=value; SameSite=Strict'.format(name=cookie.name))

            if issues:
                result.findings.append(FindingResult(
                    severity="medium",
                    title=f"Insecure cookie: {cookie.name}",
                    description=f"Cookie '{cookie.name}' has issues: {', '.join(issues)}.",
                    impact=" ".join(impacts) + " If this is a session cookie, an attacker who exploits any of these can impersonate users and take over their accounts.",
                    evidence=f"Cookie: {cookie.name}, Domain: {cookie.domain}",
                    url=url,
                    remediation="Set Secure, HttpOnly, and SameSite=Strict flags on all session cookies.",
                    remediation_example="# Full secure cookie header\nSet-Cookie: {name}=value; Secure; HttpOnly; SameSite=Strict; Path=/\n\n# Express.js\napp.use(session({{\n  cookie: {{ secure: true, httpOnly: true, sameSite: 'strict' }}\n}}));\n\n# Django settings.py\nSESSION_COOKIE_SECURE = True\nSESSION_COOKIE_HTTPONLY = True\nSESSION_COOKIE_SAMESITE = 'Strict'".format(name=cookie.name),
                ))

    def _check_tls(self, url: str, result: ScanResult):
        """Check if HTTPS is enforced."""
        if url.startswith("http://"):
            result.findings.append(FindingResult(
                severity="high",
                title="HTTPS not enforced",
                description="The target is accessible over unencrypted HTTP. All data between users and the server is transmitted in plaintext.",
                impact="Every request and response — login credentials, session tokens, personal data, API calls — can be read and modified by anyone on the network path. This includes ISPs, WiFi operators, and attackers using tools like Wireshark or mitmproxy. This is especially dangerous on public WiFi networks.",
                url=url,
                remediation="Force all traffic to HTTPS and enable HSTS to prevent downgrade attacks.",
                remediation_example="# Nginx — redirect HTTP to HTTPS\nserver {\n    listen 80;\n    return 301 https://$host$request_uri;\n}\nserver {\n    listen 443 ssl;\n    add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;\n}\n\n# Cloudflare: Enable \"Always Use HTTPS\" in SSL/TLS settings",
            ))

    def _check_error_handling(self, resp: httpx.Response, result: ScanResult, url: str):
        """Check for verbose error information."""
        body = resp.text.lower()
        stack_trace_indicators = [
            "traceback (most recent call last)",
            "at java.", "at com.", "at org.",
            "exception in thread",
            "stack trace:",
            "microsoft.aspnet",
            "fatal error",
            "syntax error",
        ]
        for indicator in stack_trace_indicators:
            if indicator in body:
                result.findings.append(FindingResult(
                    severity="medium",
                    title="Verbose error information disclosed",
                    description=f"The response body contains stack trace or debug information (matched: '{indicator}'). Internal implementation details are being exposed to users.",
                    impact="Stack traces reveal internal file paths, library versions, database types, and code structure. Attackers use this to identify vulnerable dependencies, understand your architecture, and craft targeted exploits. It can also leak sensitive data embedded in variable values.",
                    url=url,
                    remediation="Configure custom error pages for production that show generic messages without internal details.",
                    remediation_example="# FastAPI\n@app.exception_handler(Exception)\nasync def generic_exception_handler(request, exc):\n    return JSONResponse(status_code=500, content={\"error\": \"Internal server error\"})\n\n# Django settings.py\nDEBUG = False  # NEVER True in production\n\n# Express.js\napp.use((err, req, res, next) => {\n  console.error(err);  // Log internally\n  res.status(500).json({ error: 'Internal server error' });  // Generic response\n});",
                ))
                break

    def _check_rate_limiting(self, resp: httpx.Response, result: ScanResult, url: str):
        """Check for rate limiting headers."""
        rate_limit_headers = [
            "x-ratelimit-limit", "x-rate-limit-limit",
            "ratelimit-limit", "retry-after",
        ]
        has_rate_limit = any(
            h.lower() in {k.lower() for k in resp.headers}
            for h in rate_limit_headers
        )
        if not has_rate_limit:
            result.findings.append(FindingResult(
                severity="low",
                title="No rate limiting detected",
                description="No rate limiting headers (X-RateLimit-Limit, Retry-After, etc.) were found in the response, suggesting the API does not enforce request rate limits.",
                impact="Without rate limiting, attackers can make unlimited requests to brute-force login credentials, enumerate user accounts, scrape data at scale, or overwhelm your API with automated traffic. Login endpoints are especially at risk — an attacker can try thousands of passwords per second.",
                url=url,
                remediation="Implement rate limiting on all endpoints, with stricter limits on authentication and sensitive operations.",
                remediation_example="# Express.js with express-rate-limit\nconst rateLimit = require('express-rate-limit');\napp.use('/api/login', rateLimit({\n  windowMs: 15 * 60 * 1000,  // 15 minutes\n  max: 5,                     // 5 attempts per window\n  message: 'Too many login attempts'\n}));\n\n# Nginx\nlimit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;\nlocation /api/login {\n    limit_req zone=login burst=3 nodelay;\n}",
            ))
