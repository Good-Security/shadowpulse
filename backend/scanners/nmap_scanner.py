import xml.etree.ElementTree as ET
from datetime import datetime

from scanners.base import BaseScanner, ScanResult, FindingResult, AssetArtifact, ServiceArtifact
from recongraph.normalize import normalize_domain, guess_asset_type_from_host


class NmapScanner(BaseScanner):
    name = "nmap"
    binary = "nmap"

    async def run(self, target: str, config: dict | None = None, stream_callback=None) -> ScanResult:
        config = config or {}
        ports = config.get("ports", "")
        scan_type = config.get("scan_type", "service")  # quick, service, full

        result = ScanResult(
            scanner=self.name,
            target=target,
            started_at=datetime.utcnow(),
        )

        # Build nmap command
        cmd = ["nmap"]

        if scan_type == "quick":
            cmd += ["-T4", "-F"]
        elif scan_type == "full":
            cmd += ["-sV", "-sC", "-A", "-T4"]
        else:  # service (default)
            cmd += ["-sV", "-sC", "-T4"]

        if ports:
            cmd += ["-p", ports]

        cmd += ["-oX", "-", target]  # XML output to stdout

        try:
            stdout, stderr, returncode = await self.exec_in_container(cmd, timeout=600, stream_callback=stream_callback)
            result.raw_output = stdout
            findings, assets, services = self._parse_xml(stdout, target)
            result.findings = findings
            result.assets = assets
            result.services = services
            result.status = "completed"
        except Exception as e:
            result.status = "failed"
            result.error = str(e)

        result.completed_at = datetime.utcnow()
        return result

    def _parse_xml(self, xml_str: str, target: str) -> tuple[list[FindingResult], list[AssetArtifact], list[ServiceArtifact]]:
        findings: list[FindingResult] = []
        assets: list[AssetArtifact] = []
        services: list[ServiceArtifact] = []

        try:
            root = ET.fromstring(xml_str)
        except ET.ParseError:
            return findings, assets, services

        for host in root.findall(".//host"):
            addr_el = host.find("address")
            addr = addr_el.get("addr", target) if addr_el is not None else target
            host_type = guess_asset_type_from_host(addr)
            host_norm = normalize_domain(addr)

            if host_norm:
                assets.append(AssetArtifact(type=host_type, value=addr, normalized=host_norm))

            for port in host.findall(".//port"):
                portid = port.get("portid", "")
                protocol = port.get("protocol", "tcp")
                state_el = port.find("state")
                state = state_el.get("state", "") if state_el is not None else ""

                if state != "open":
                    continue

                service_el = port.find("service")
                service_name = service_el.get("name", "unknown") if service_el is not None else "unknown"
                product = service_el.get("product", "") if service_el is not None else ""
                version = service_el.get("version", "") if service_el is not None else ""

                try:
                    port_int = int(portid)
                except (ValueError, TypeError):
                    port_int = 0

                service_desc = f"{service_name}"
                if product:
                    service_desc += f" ({product}"
                    if version:
                        service_desc += f" {version}"
                    service_desc += ")"

                if host_norm and port_int > 0:
                    services.append(ServiceArtifact(
                        host_type=host_type,
                        host_value=addr,
                        host_normalized=host_norm,
                        port=port_int,
                        proto=protocol,
                        name=service_name,
                        product=product,
                        version=version,
                    ))

                findings.append(FindingResult(
                    severity="info",
                    title=f"Open port {portid}/{protocol} - {service_desc}",
                    description=f"Port {portid}/{protocol} is open on {addr} running {service_desc}",
                    url=f"{addr}:{portid}",
                ))

                # Check for script results (vulns, etc.)
                for script in port.findall(".//script"):
                    script_id = script.get("id", "")
                    script_output = script.get("output", "")

                    if any(kw in script_id.lower() for kw in ["vuln", "exploit", "cve"]):
                        findings.append(FindingResult(
                            severity="high",
                            title=f"Nmap script: {script_id} on port {portid}",
                            description=script_output[:500],
                            evidence=script_output,
                            url=f"{addr}:{portid}",
                        ))

        return findings, assets, services
