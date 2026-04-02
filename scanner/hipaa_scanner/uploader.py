"""
Upload scan results to the HIPAA Scanner web platform.
"""

from __future__ import annotations
import json
from pathlib import Path
import httpx
from .models import ScanReport


class ScanUploader:
    def __init__(self, api_base_url: str, api_key: str):
        self.api_base_url = api_base_url.rstrip("/")
        self.api_key = api_key

    def upload(self, report: ScanReport) -> dict:
        """POST scan results to platform API. Returns API response."""
        payload = report.model_dump(mode="json")
        headers = {
            "X-Scanner-API-Key": self.api_key,
            "Content-Type": "application/json",
        }
        with httpx.Client(timeout=60.0) as client:
            response = client.post(
                f"{self.api_base_url}/api/v1/scans/upload",
                json=payload,
                headers=headers,
            )
            response.raise_for_status()
            return response.json()

    def save_local(self, report: ScanReport, output_path: Path) -> None:
        """Save scan report as JSON for offline/air-gapped environments."""
        output_path.write_text(
            json.dumps(report.model_dump(mode="json"), indent=2, default=str)
        )
