from datetime import datetime

from scanners.base import BaseScanner, ScanResult, FindingResult, AssetArtifact, EdgeArtifact
from recongraph.normalize import normalize_domain, is_ip


class DnsxScanner(BaseScanner):
    """DNS enumeration and record analysis using dnsx — checks for misconfigurations, dangling records, and zone info."""

    name = "dnsx"
    binary = "dnsx"

    async def run(self, target: str, config: dict | None = None, stream_callback=None) -> ScanResult:
        config = config or {}
        result = ScanResult(
            scanner=self.name,
            target=target,
            started_at=datetime.utcnow(),
        )

        # Strip to domain only
        domain = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        self._stream = stream_callback

        try:
            # Run multiple DNS queries
            await self._emit(f"[dns] Querying A records for {domain}")
            a_records = await self._query(domain, "a")

            await self._emit(f"[dns] Querying AAAA records for {domain}")
            aaaa_records = await self._query(domain, "aaaa")

            await self._emit(f"[dns] Querying MX records for {domain}")
            mx_records = await self._query(domain, "mx")

            await self._emit(f"[dns] Querying NS records for {domain}")
            ns_records = await self._query(domain, "ns")

            await self._emit(f"[dns] Querying TXT records for {domain}")
            txt_records = await self._query(domain, "txt")

            await self._emit(f"[dns] Querying CNAME records for {domain}")
            cname_records = await self._query(domain, "cname")

            await self._emit(f"[dns] Querying SOA records for {domain}")
            soa_records = await self._query(domain, "soa")

            # Analyze results
            all_records = {
                "A": a_records, "AAAA": aaaa_records, "MX": mx_records,
                "NS": ns_records, "TXT": txt_records, "CNAME": cname_records,
                "SOA": soa_records,
            }

            result.raw_output = "\n".join(
                f"{rtype}: {', '.join(records) if records else 'none'}"
                for rtype, records in all_records.items()
            )

            # Artifacts: domain and any resolved IPs / CNAMEs.
            dom_norm = normalize_domain(domain)
            if dom_norm:
                result.assets.append(AssetArtifact(type="subdomain", value=domain, normalized=dom_norm))

            for ip in (a_records or []) + (aaaa_records or []):
                ip_norm = ip.strip()
                if not ip_norm:
                    continue
                if is_ip(ip_norm):
                    result.assets.append(AssetArtifact(type="ip", value=ip_norm, normalized=ip_norm))
                    if dom_norm:
                        result.edges.append(EdgeArtifact(
                            from_type="subdomain",
                            from_value=domain,
                            from_normalized=dom_norm,
                            to_type="ip",
                            to_value=ip_norm,
                            to_normalized=ip_norm,
                            rel_type="resolves_to",
                        ))

            for cname in cname_records or []:
                cname_norm = normalize_domain(cname)
                if cname_norm and dom_norm:
                    result.assets.append(AssetArtifact(type="host", value=cname, normalized=cname_norm))
                    result.edges.append(EdgeArtifact(
                        from_type="subdomain",
                        from_value=domain,
                        from_normalized=dom_norm,
                        to_type="host",
                        to_value=cname,
                        to_normalized=cname_norm,
                        rel_type="cname_to",
                    ))

            result.findings = self._analyze(domain, all_records)
            result.status = "completed"
        except Exception as e:
            result.status = "failed"
            result.error = str(e)

        result.completed_at = datetime.utcnow()
        return result

    async def _emit(self, line: str):
        if self._stream:
            await self._stream(line)

    async def _query(self, domain: str, record_type: str) -> list[str]:
        """Query a specific DNS record type."""
        cmd = ["sh", "-c", f"echo {domain} | dnsx -silent -{record_type} -resp-only"]
        try:
            stdout, stderr, returncode = await self.exec_in_container(cmd, timeout=30)
            records = [line.strip() for line in stdout.strip().split("\n") if line.strip()]
            for r in records:
                if self._stream:
                    await self._stream(f"[dns] {record_type.upper()}: {r}")
            return records
        except Exception:
            return []

    def _analyze(self, domain: str, records: dict) -> list[FindingResult]:
        findings = []

        # Report discovered records as info
        for rtype, values in records.items():
            if values:
                findings.append(FindingResult(
                    severity="info",
                    title=f"DNS {rtype} records for {domain}",
                    description=f"Found {len(values)} {rtype} record(s): {', '.join(values[:10])}",
                    impact=f"DNS {rtype} records reveal infrastructure details. Attackers use this for reconnaissance to map your hosting provider, mail infrastructure, and service dependencies.",
                    evidence="\n".join(values),
                    url=domain,
                ))

        # Check for SPF
        txt_records = records.get("TXT", [])
        has_spf = any("v=spf1" in t.lower() for t in txt_records)
        if not has_spf:
            findings.append(FindingResult(
                severity="medium",
                title="Missing SPF record",
                description=f"No SPF (Sender Policy Framework) TXT record found for {domain}. Without SPF, anyone can send emails that appear to come from your domain.",
                impact="Attackers can send phishing emails that appear to come from your domain. Email recipients and spam filters cannot verify whether the sender is authorized. This is commonly exploited in business email compromise (BEC) and phishing campaigns.",
                url=domain,
                remediation="Add an SPF TXT record to your DNS zone specifying which servers can send email for your domain.",
                remediation_example=f'# Add this TXT record to your DNS:\n{domain}. IN TXT "v=spf1 include:_spf.google.com ~all"\n\n# For multiple providers:\n{domain}. IN TXT "v=spf1 include:_spf.google.com include:sendgrid.net -all"\n\n# If you don\'t send email from this domain:\n{domain}. IN TXT "v=spf1 -all"',
            ))

        # Check for DMARC
        has_dmarc = any("v=dmarc1" in t.lower() for t in txt_records)
        if not has_dmarc:
            findings.append(FindingResult(
                severity="medium",
                title="Missing DMARC record",
                description=f"No DMARC (Domain-based Message Authentication, Reporting & Conformance) record found for {domain}.",
                impact="Without DMARC, you have no policy enforcement for email authentication. Even with SPF, receiving servers may still accept spoofed emails. DMARC provides reporting on authentication failures and policy enforcement (reject/quarantine).",
                url=domain,
                remediation="Add a DMARC TXT record at _dmarc.yourdomain.com.",
                remediation_example=f'# Start with monitoring mode (p=none), then tighten:\n_dmarc.{domain}. IN TXT "v=DMARC1; p=none; rua=mailto:dmarc@{domain}; fo=1"\n\n# Once you\'re confident, enforce:\n_dmarc.{domain}. IN TXT "v=DMARC1; p=reject; rua=mailto:dmarc@{domain}; fo=1"',
            ))

        # Check for DKIM hint
        has_dkim = any("dkim" in t.lower() for t in txt_records)
        if not has_dkim and (has_spf or records.get("MX")):
            findings.append(FindingResult(
                severity="low",
                title="No DKIM records detected",
                description=f"No DKIM (DomainKeys Identified Mail) signatures detected in TXT records for {domain}. Note: DKIM records are usually at selector._domainkey.{domain} and may not be visible in a general query.",
                impact="Without DKIM, email recipients cannot verify that messages haven't been tampered with in transit. DKIM provides cryptographic signing of email headers and body, preventing modification by intermediate mail servers.",
                url=domain,
                remediation="Configure DKIM signing with your email provider and publish the public key as a DNS TXT record.",
                remediation_example=f"# DKIM is typically configured through your email provider\n# (Google Workspace, Microsoft 365, SendGrid, etc.)\n\n# The DNS record looks like:\nselecor1._domainkey.{domain}. IN TXT \"v=DKIM1; k=rsa; p=<public-key>\"\n\n# Check: dig TXT selector1._domainkey.{domain}",
            ))

        # Check for CNAME records that might indicate dangling DNS
        cname_records = records.get("CNAME", [])
        cloud_providers = ["amazonaws.com", "azurewebsites.net", "cloudfront.net",
                          "herokuapp.com", "github.io", "pages.dev", "netlify.app",
                          "vercel.app", "s3.amazonaws.com", "elasticbeanstalk.com"]
        for cname in cname_records:
            for provider in cloud_providers:
                if provider in cname.lower():
                    findings.append(FindingResult(
                        severity="low",
                        title=f"Cloud service CNAME: {cname}",
                        description=f"The domain {domain} has a CNAME pointing to {cname}. If this cloud resource is unclaimed, it may be vulnerable to subdomain takeover.",
                        impact="If the target cloud resource (S3 bucket, Heroku app, Azure site, etc.) has been deleted but the CNAME record remains, an attacker can claim the resource and serve malicious content on your domain. This is a subdomain takeover vulnerability.",
                        evidence=f"CNAME: {domain} → {cname}",
                        url=domain,
                        remediation="Verify the cloud resource still exists. Remove CNAME records that point to deprovisioned services.",
                        remediation_example=f"# Check if the target responds:\ncurl -I {cname}\n\n# If it returns an error (NoSuchBucket, Not Found, etc.),\n# remove the CNAME record immediately:\n# DNS: Remove CNAME {domain} → {cname}",
                    ))

        return findings
