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

def query_loki_instant(settings: Settings, logql: str) -> Dict[str, Any]:
    """
    Instant query: returns a single value at 'now' (good for aggregations like sum(count_over_time(...))).
    """
    url = f"{settings.loki_url}/loki/api/v1/query"
    params = {"query": logql}
    r = requests.get(url, params=params, timeout=15)
    r.raise_for_status()
    return r.json()

def _first_scalar(resp: Dict[str, Any]) -> Optional[float]:
    """
    Loki instant query returns:
    data.resultType = "vector"
    data.result[0].value = [ <ts>, "<number>" ]
    """
    try:
        result = resp.get("data", {}).get("result", [])
        if not result:
            return 0.0
        value = result[0].get("value", [])
        if len(value) < 2:
            return 0.0
        return float(value[1])
    except Exception:
        return None


def _first_int(resp: Dict[str, Any]) -> Optional[int]:
    v = _first_scalar(resp)
    if v is None:
        return None
    if v.is_integer():
        return int(v)
    return int(round(v))
    
def collect_error_logs(settings: Settings) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Collect recent error logs (samples) and an estimated total count over lookback window.
    """
    selector = _ns_app_error_selector(settings)

    # A) 样本查询：拿最近 N 条 ERROR（用于报告展示）
    sample_logql = f'{selector} |~ "(?i)error"'
    sample_resp = query_loki(settings, sample_logql, limit=50)

    rows = []
    try:
        results = sample_resp.get("data", {}).get("result", [])
        for stream in results:
            for ts, line in stream.get("values", []):
                rows.append({"ts": ts, "line": line})
    except Exception:
        rows = []

    rows = sorted(rows, key=lambda x: x["ts"], reverse=True)

    # B) 统计查询：算 lookback window 内 ERROR 的总量（不受 limit 影响）
    # 注意：count_over_time 需要 range selector，所以用 [{lookback}m]
    count_logql = (
        f'sum(count_over_time({selector} |~ "(?i)error" [{settings.lookback_minutes}m]))'
    )
    count_resp = query_loki_instant(settings, count_logql)
    error_count = _first_int(count_resp)

    loki_queries = {
        "error_logs": {
            "query": sample_logql,
            "response": sample_resp,
            "rows": rows[:20],  # 报告里最多放 20 行样本
        },
        "error_logs_count": {
            "query": count_logql,
            "response": count_resp,
            "scalar": error_count,
        },
    }

    summary = {
        # 真正的统计（面试/告警更有意义）
        "error_log_count": error_count if error_count is not None else 0,
        # 样本数量（用于解释“为什么 rows 只有 20/50”）
        "error_log_sample_count": len(rows),
    }

    return loki_queries, summary
