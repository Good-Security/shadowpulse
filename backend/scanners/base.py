import asyncio
import json
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional

from config import settings


@dataclass
class FindingResult:
    severity: str  # critical, high, medium, low, info
    title: str
    description: str = ""
    impact: str = ""  # Why this is dangerous / what happens if left unfixed
    evidence: str = ""
    remediation: str = ""
    remediation_example: str = ""  # Code/config snippet showing how to fix
    url: str = ""
    cve: str = ""
    cvss_score: float = 0.0

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class AssetArtifact:
    type: str  # subdomain, host, ip, url
    value: str
    normalized: str


@dataclass
class ServiceArtifact:
    host_type: str  # host, ip, subdomain
    host_value: str
    host_normalized: str
    port: int
    proto: str  # tcp, udp
    name: str = ""
    product: str = ""
    version: str = ""


@dataclass
class EdgeArtifact:
    from_type: str
    from_value: str
    from_normalized: str
    to_type: str
    to_value: str
    to_normalized: str
    rel_type: str  # resolves_to, serves, redirects_to, etc


@dataclass
class ScanResult:
    scanner: str
    target: str
    status: str = "completed"  # completed, failed
    raw_output: str = ""
    findings: list[FindingResult] = field(default_factory=list)
    assets: list[AssetArtifact] = field(default_factory=list)
    services: list[ServiceArtifact] = field(default_factory=list)
    edges: list[EdgeArtifact] = field(default_factory=list)
    error: str = ""
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    def to_dict(self) -> dict:
        d = asdict(self)
        d["started_at"] = self.started_at.isoformat() if self.started_at else None
        d["completed_at"] = self.completed_at.isoformat() if self.completed_at else None
        return d


class BaseScanner(ABC):
    """Base class for all security scanners."""

    name: str = "base"

    def is_available(self) -> bool:
        """Check if the scanner tool is available in the tools container."""
        try:
            result = subprocess.run(
                ["docker", "exec", settings.TOOLS_CONTAINER, "which", self.binary],
                capture_output=True, text=True, timeout=5
            )
            return result.returncode == 0
        except Exception:
            return False

    @property
    @abstractmethod
    def binary(self) -> str:
        """The binary name of the tool."""
        ...

    @abstractmethod
    async def run(self, target: str, config: dict | None = None, stream_callback=None) -> ScanResult:
        """Execute the scan and return results. stream_callback(line) streams raw output."""
        ...

    async def exec_in_container(
        self,
        cmd: list[str],
        timeout: int = 300,
        stream_callback=None,
    ) -> tuple[str, str, int]:
        """Execute a command in the tools Docker container."""
        full_cmd = ["docker", "exec", settings.TOOLS_CONTAINER] + cmd

        process = await asyncio.create_subprocess_exec(
            *full_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        stdout_parts: list[str] = []
        stderr_text = ""

        async def _read_stdout():
            assert process.stdout is not None
            async for line in process.stdout:
                decoded = line.decode(errors="replace").rstrip()
                if not decoded:
                    continue
                stdout_parts.append(decoded)
                if stream_callback:
                    await stream_callback(decoded)

        async def _read_stderr() -> str:
            if not process.stderr:
                return ""
            data = await process.stderr.read()
            return data.decode(errors="replace")

        try:
            if stream_callback:
                stdout_task = asyncio.create_task(_read_stdout())
                stderr_task = asyncio.create_task(_read_stderr())

                await asyncio.wait_for(process.wait(), timeout=timeout)

                # Drain stdout/stderr tasks after completion.
                await stdout_task
                stderr_text = await stderr_task
            else:
                stdout_data, stderr_data = await asyncio.wait_for(
                    process.communicate(), timeout=timeout
                )
                stdout_parts = [stdout_data.decode(errors="replace").rstrip()]
                stderr_text = stderr_data.decode(errors="replace")
        except asyncio.TimeoutError:
            process.kill()
            try:
                await process.wait()
            except Exception:
                pass
            raise TimeoutError(f"Command timed out after {timeout}s: {' '.join(cmd)}")

        returncode = process.returncode if process.returncode is not None else -1
        stdout = "\n".join([p for p in stdout_parts if p is not None])
        return stdout, stderr_text, returncode
