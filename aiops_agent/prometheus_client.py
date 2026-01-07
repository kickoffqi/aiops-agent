from dataclasses import dataclass
from typing import Any, Dict, Optional
import time

import requests


@dataclass
class PrometheusClient:
    """
    Minimal Prometheus HTTP API client for AIOps.
    """
    base_url: str
    headers: Dict[str, str]
    auth: Optional[object] = None
    timeout: int = 15

    def query(self, promql: str, ts: Optional[float] = None) -> Dict[str, Any]:
        """
        Instant query.
        """
        url = f"{self.base_url}/api/v1/query"
        params = {"query": promql}
        if ts is not None:
            params["time"] = ts

        resp = requests.get(
            url,
            params=params,
            headers=self.headers,
            auth=self.auth,
            timeout=self.timeout,
        )

        resp.raise_for_status()
        return resp.json()

    def query_range(
        self,
        promql: str,
        start: float,
        end: float,
        step: str = "30s",
    ) -> Dict[str, Any]:
        """
        Range query.
        """
        url = f"{self.base_url}/api/v1/query_range"
        params = {
            "query": promql,
            "start": start,
            "end": end,
            "step": step,
        }

        resp = requests.get(
            url,
            params=params,
            headers=self.headers,
            auth=self.auth,
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.json()