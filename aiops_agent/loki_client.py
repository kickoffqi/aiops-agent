from dataclasses import dataclass
from .http import get_json

@dataclass
class LokiClient:
    base_url: str
    headers: dict
    auth: object | None = None

    def query_range(self, logql: str, start_ns: int, end_ns: int, limit: int = 200) -> dict:
        """
        Loki uses nanoseconds timestamps for query_range.
        """
        url = f"{self.base_url}/loki/api/v1/query_range"
        return get_json(
            url,
            params={"query": logql, "start": start_ns, "end": end_ns, "limit": limit, "direction": "BACKWARD"},
            headers=self.headers,
            auth=self.auth,
        )