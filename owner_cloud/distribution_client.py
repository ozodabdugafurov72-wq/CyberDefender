from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any


class DistributionClient:
    MAX_RESPONSE = 1024 * 1024

    def __init__(self, base_url: str, token: str, *, timeout: float = 3.0):
        self.base_url = str(base_url).rstrip("/")
        self.token = str(token)
        self.timeout = max(0.5, min(float(timeout), 10.0))

    def state(self) -> dict[str, Any]:
        if not self.base_url or not self.token:
            return {"status": "UNAVAILABLE", "reason": "NOT_CONFIGURED"}
        request = urllib.request.Request(
            self.base_url + "/api/v1/owner/summary",
            headers={
                "Accept": "application/json",
                "Authorization": "Bearer " + self.token,
                "User-Agent": "CyberDefenderOwnerCloud",
            },
            method="GET",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                raw = response.read(self.MAX_RESPONSE + 1)
                if response.status != 200 or len(raw) > self.MAX_RESPONSE:
                    return {"status": "UNAVAILABLE", "reason": "UPSTREAM_RESPONSE_REJECTED"}
            value = json.loads(raw.decode("utf-8"))
            if not isinstance(value, dict):
                raise ValueError("object required")
            value["transport"] = "RAILWAY_PRIVATE_AUTHENTICATED"
            return value
        except (OSError, ValueError, urllib.error.URLError, json.JSONDecodeError):
            return {"status": "UNAVAILABLE", "reason": "UPSTREAM_UNAVAILABLE"}
