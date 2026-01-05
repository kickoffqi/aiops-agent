from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple
import requests
from datetime import datetime, timezone, timedelta

from ..config import Settings


def _ns_app_error_selector(settings: Settings) -> str:
    # 先用最通用的标签：namespace + (可选 app)
    # 注意：不同 promtail 版本标签可能是 namespace / pod / container / job 等
    # 我们先以 namespace 为主，后续再收紧到 app_label
    #return f'{{namespace="{settings.namespace}"}}'
    return f'{{namespace="{settings.namespace}", app="{settings.app_label}"}}'


def query_loki(settings: Settings, logql: str, limit: int = 20) -> Dict[str, Any]:
    url = f"{settings.loki_url}/loki/api/v1/query_range"
    end = datetime.now(timezone.utc)
    start = end - timedelta(minutes=settings.lookback_minutes)

    params = {
        "query": logql,
        "start": int(start.timestamp() * 1e9),
        "end": int(end.timestamp() * 1e9),
        "limit": limit,
        "direction": "BACKWARD",
    }
    r = requests.get(url, params=params, timeout=15)
    r.raise_for_status()
    return r.json()


def collect_error_logs(settings: Settings) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Collect recent error logs for the namespace.
    Returns:
      loki_queries: dict
      summary: dict
    """
    selector = _ns_app_error_selector(settings)

    # 最简单：找包含 "error" / "ERROR" 的日志
    logql = f'{selector} |~ "(?i)error"'

    resp = query_loki(settings, logql, limit=50)

    # 解析返回，抽取若干行样本
    rows = []
    try:
        results = resp.get("data", {}).get("result", [])
        for stream in results:
            for ts, line in stream.get("values", []):
                rows.append({"ts": ts, "line": line})
    except Exception:
        rows = []

    # 最新在前（BACKWARD 通常已是新→旧，但这里再保险排序）
    rows = sorted(rows, key=lambda x: x["ts"], reverse=True)

    loki_queries = {
        "error_logs": {
            "query": logql,
            "response": resp,
            "rows": rows[:20],  # 报告里最多放 20 行样本
        }
    }

    summary = {
        "error_log_count": len(rows),
    }

    return loki_queries, summary
