"""
API Service for OWASP Scanner Backend
Real-time scan orchestration client
"""

import json
from typing import Callable, Optional
import requests
from dataclasses import dataclass
from datetime import datetime
from enum import Enum


class ScanStatus(Enum):
    INITIALIZING = "initializing"
    RUNNING = "running"
    COMPLETED = "completed"
    ERROR = "error"
    CANCELLED = "cancelled"


@dataclass
class Finding:
    id: str
    file: str
    line_number: int
    severity: str
    title: str
    description: str
    matched_content: str
    cwe: str
    remediation: str
    confidence: float
    tags: list
    category: str
    module: str
    module_name: str
    owasp: str
    timestamp: str


@dataclass
class ScanResult:
    scan_id: str
    status: str
    target: str
    duration: float
    started_at: Optional[str]
    completed_at: Optional[str]
    total_findings: int
    summary: dict
    module_summary: dict
    findings: list[Finding]
    logs: list[dict]


class ScannerAPI:
    """Client for the OWASP Scanner FastAPI backend."""

    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()

    def health_check(self) -> dict:
        """Check backend health status."""
        response = self.session.get(f"{self.base_url}/api/v1/health")
        response.raise_for_status()
        return response.json()

    def list_modules(self) -> list[dict]:
        """Get available scanner modules."""
        response = self.session.get(f"{self.base_url}/api/v1/modules")
        response.raise_for_status()
        return response.json().get("modules", [])

    def start_scan(
        self,
        target: str,
        modules: list[str],
        scan_type: str = "directory",
        scan_profile: str = "full"
    ) -> str:
        """
        Start a new scan.

        Args:
            target: Path to directory or code content
            modules: List of module keys to run
            scan_type: "directory" or "code"
            scan_profile: "full", "quick", or "custom"

        Returns:
            scan_id: UUID of the started scan
        """
        payload = {
            "target": target,
            "modules": modules,
            "scan_type": scan_type,
            "scan_profile": scan_profile
        }
        response = self.session.post(
            f"{self.base_url}/api/v1/scan/start",
            json=payload
        )
        response.raise_for_status()
        return response.json()["scan_id"]

    def get_scan_status(self, scan_id: str) -> dict:
        """Get current scan status and progress."""
        response = self.session.get(
            f"{self.base_url}/api/v1/scan/{scan_id}/status"
        )
        response.raise_for_status()
        return response.json()

    def cancel_scan(self, scan_id: str) -> dict:
        """Cancel a running scan."""
        response = self.session.post(
            f"{self.base_url}/api/v1/scan/{scan_id}/cancel"
        )
        response.raise_for_status()
        return response.json()

    def get_scan_report(self, scan_id: str) -> ScanResult:
        """Get complete scan report with all findings."""
        response = self.session.get(
            f"{self.base_url}/api/v1/scan/{scan_id}/report"
        )
        response.raise_for_status()
        data = response.json()

        findings = [self._parse_finding(f) for f in data.get("findings", [])]

        return ScanResult(
            scan_id=data["scan_id"],
            status=data["status"],
            target=data["target"],
            duration=data.get("duration", 0),
            started_at=data.get("started_at"),
            completed_at=data.get("completed_at"),
            total_findings=data.get("total_findings", 0),
            summary=data.get("summary", {}),
            module_summary=data.get("module_summary", {}),
            findings=findings,
            logs=data.get("logs", [])
        )

    def list_scans(self) -> list[dict]:
        """List all scans."""
        response = self.session.get(f"{self.base_url}/api/v1/scans")
        response.raise_for_status()
        return response.json().get("scans", [])

    def stream_scan_events(
        self,
        scan_id: str,
        on_finding: Optional[Callable[[Finding], None]] = None,
        on_log: Optional[Callable[[dict], None]] = None,
        on_status: Optional[Callable[[dict], None]] = None,
        on_complete: Optional[Callable[[dict], None]] = None
    ):
        """
        Stream real-time scan events via SSE.

        Args:
            scan_id: The scan to stream
            on_finding: Callback for new finding events
            on_log: Callback for log messages
            on_status: Callback for status updates
            on_complete: Callback when scan completes
        """
        import sseclient

        url = f"{self.base_url}/api/v1/scan/{scan_id}/stream"
        response = self.session.get(url, stream=True, headers={
            "Accept": "text/event-stream"
        })
        response.raise_for_status()

        client = sseclient.SSEClient(response)

        for event in client.events():
            try:
                data = json.loads(event.data) if event.data else {}

                if event.event == "finding" and on_finding:
                    finding = self._parse_finding(data)
                    on_finding(finding)

                elif event.event == "log" and on_log:
                    on_log(data)

                elif event.event == "status" and on_status:
                    on_status(data)

                elif event.event == "complete" and on_complete:
                    on_complete(data)

            except json.JSONDecodeError:
                continue
            except Exception:
                continue

    def _parse_finding(self, data: dict) -> Finding:
        """Parse finding from API response."""
        return Finding(
            id=data.get("id", ""),
            file=data.get("file", ""),
            line_number=data.get("line_number", 0),
            severity=data.get("severity", "info"),
            title=data.get("title", ""),
            description=data.get("description", ""),
            matched_content=data.get("matched_content", data.get("matched_value", "")),
            cwe=data.get("cwe", ""),
            remediation=data.get("remediation", ""),
            confidence=data.get("confidence", 0.0),
            tags=data.get("tags", []),
            category=data.get("category", ""),
            module=data.get("module", ""),
            module_name=data.get("module_name", ""),
            owasp=data.get("owasp", ""),
            timestamp=data.get("timestamp", datetime.now().isoformat())
        )


def get_available_modules() -> list[tuple[str, str, str]]:
    """Get list of available scanner modules with descriptions."""
    return [
        ("misconfig", "Security Misconfiguration", "A02:2025"),
        ("injection", "Injection Vulnerabilities", "A05:2025"),
        ("frontend_js", "Frontend JS Analyzer", "A04:2025"),
        ("endpoint", "Endpoint Extractor", "Recon"),
        ("auth", "Auth Failures", "A07:2025"),
        ("access_control", "Broken Access Control", "A01:2025"),
        ("cloud", "Cloud Misconfiguration", "A02:2025-Cloud"),
        ("api_security", "API Security", "API-Top-10"),
        ("supply_chain", "Supply Chain", "A03:2025"),
        ("insecure_design", "Insecure Design", "A06:2025"),
        ("integrity", "Integrity Failures", "A08:2025"),
    ]
