from __future__ import annotations

import re,requests
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

from ..incident import IncidentContext
from ..config import Settings
from ..prometheus_client import PrometheusClient
from ..collector.prometheus_v2 import build_client, _first_scalar  # 你prometheus_v2里如果没导出，可复制这俩helper过来
from datetime import datetime, timezone, timedelta


def _safe_pod_regex(pods: List[str]) -> str:
    # 把 pod 名做 regex escape，然后用 (a|b|c) 组合
    esc = [re.escape(p) for p in pods if p]
    if not esc:
        return ""
    return "(" + "|".join(esc) + ")"


def _extract_pod_error_stats(ctx: IncidentContext, max_rows: int = 500) -> Dict[str, Any]:
    """
    从 Loki rows 做 per-pod 统计：error_count、samples、top_error_type（轻量版）
    依赖 rows 里带 pod/container/line/ts
    """
    rows: List[Dict[str, Any]] = []
    try:
        rows = ctx.loki_queries.get("error_logs", {}).get("rows", [])  # type: ignore[assignment]
    except Exception:
        rows = []

    by_pod: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
        "error_count": 0,
        "containers": defaultdict(int),
        "samples": [],
    })

    for r in rows[:max_rows]:
        pod = r.get("pod") or "unknown"
        container = r.get("container") or "unknown"
        line = r.get("line") or ""
        ts = r.get("ts")

        by_pod[pod]["error_count"] += 1
        by_pod[pod]["containers"][container] += 1

        # 只留少量样本，避免 report 太大
        if len(by_pod[pod]["samples"]) < 5:
            by_pod[pod]["samples"].append({"ts": ts, "line": line, "container": container})

    # containers defaultdict -> dict
    out: Dict[str, Any] = {}
    for pod, data in by_pod.items():
        data["containers"] = dict(data["containers"])
        out[pod] = data

    return out


def _prom_query_series(prom: PrometheusClient, query: str) -> Dict[str, float]:
    """
    把 Prometheus instant query 的 vector result，转成 {pod: value}
    要求 metric 里有 pod label（sum by(pod) 等）
    """


    try:
        resp = prom.query(query)
    except requests.HTTPError as e:
        print("\n--- PromQL ---")
        print(query)
        if e.response is not None:
            print("\n--- Prometheus error body ---")
            print(e.response.text)   # 这里会告诉你 parse error 的具体位置
        raise

    out: Dict[str, float] = {}
    try:
        results = resp.get("data", {}).get("result", [])
        for item in results:
            metric = item.get("metric", {}) or {}
            pod = metric.get("pod")
            v = item.get("value")
            if not pod or not v or len(v) < 2:
                continue
            out[pod] = float(v[1])
    except Exception:
        pass
    return out

from typing import Any

def prom_str(v: Any) -> str:
    if v is None:
        return ""
    if not isinstance(v, str):
        raise TypeError(f"prom_str expects str, got {type(v)}: {v!r}")
    return v.replace("\\", "\\\\").replace('"', '\\"')

def promql_escape_string(s: str) -> str:
    """
    Escape for PromQL double-quoted string literal.
    PromQL string supports escaping: \\ and \"
    """
    return s.replace("\\", "\\\\").replace('"', '\\"')

def prom_regex_from_list(values: List[str]) -> str:
    """
    Build RE2 regex matching exactly these values, safe for PromQL.
    """
    parts = []
    for v in values:
        if not v:
            continue
        # escape regex metacharacters
        escaped = re.escape(v)
        # IMPORTANT: PromQL string literal needs backslashes escaped again
        escaped = promql_escape_string(escaped)
        parts.append(escaped)

    if not parts:
        return "^$"
    return "^(%s)$" % "|".join(parts)



def query_loki_instant(settings: Settings, logql: str) -> Dict[str, Any]:
    url = f"{settings.loki_url}/loki/api/v1/query"
    t = datetime.now(timezone.utc)
    params = {
        "query": logql,
        "time": int(t.timestamp() * 1e9),
    }
    r = requests.get(url, params=params, timeout=15)
    r.raise_for_status()
    return r.json()


def query_loki_range(settings: Settings, logql: str, limit: int = 20) -> Dict[str, Any]:
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

def _loki_error_counts_by_pod(settings: Settings) -> Tuple[str, Dict[str, float], Dict[str, Any]]:
    selector = f'{{namespace="{settings.namespace}", app="{settings.app_label}"}}'
    # 统计整个窗口内 error 条数（按 pod）
    q = (
        'sum by (pod) ('
        f'count_over_time({selector} |~ "(?i)error" [{settings.lookback_minutes}m])'
        ')'
    )
    resp = query_loki_instant(settings, q)

    out: Dict[str, float] = {}
    try:
        results = resp.get("data", {}).get("result", [])
        for item in results:
            metric = item.get("metric") or {}
            pod = metric.get("pod")
            v = item.get("value")
            if not pod or not v or len(v) < 2:
                continue
            out[pod] = float(v[1])
    except Exception:
        pass

    return q, out, resp

def _loki_error_samples_for_pod(settings: Settings, pod: str, limit: int = 5) -> Tuple[str, List[Dict[str, Any]], Dict[str, Any]]:
    selector = (
        f'{{namespace="{settings.namespace}", app="{settings.app_label}", pod="{pod}"}}'
    )
    q = f'{selector} |~ "(?i)error"'
    resp = query_loki_range(settings, q, limit=limit)

    rows: List[Dict[str, Any]] = []
    try:
        results = resp.get("data", {}).get("result", [])
        for stream in results:
            labels = stream.get("stream") or {}
            container = labels.get("container")
            pod_name = labels.get("pod")
            for ts, line in stream.get("values", []):
                rows.append({"ts": ts, "line": line, "container": container, "pod": pod_name})
    except Exception:
        pass

    rows = sorted(rows, key=lambda x: x["ts"], reverse=True)
    return q, rows[:limit], resp

def correlate_prom_loki(ctx: IncidentContext, settings: Settings, top_n: int = 5) -> Dict[str, Any]:
    # --- 1) Loki stats (按 pod 统计) ---
    try:
        q_loki_stats, counts_by_pod, resp_loki_stats = _loki_error_counts_by_pod(settings)
        loki_ok = True
        loki_err = None
    except Exception as e:
        loki_ok = False
        loki_err = str(e)
        q_loki_stats, counts_by_pod, resp_loki_stats = "", {}, {}

    if not loki_ok:
        corr = {
            "status": "loki_error",
            "loki_error": loki_err,
        }
        ctx.summary["correlation"] = corr
        # 同时把 loki_status 标为 error（如果你希望在 report 里看到）
        ctx.summary["loki_status"] = "error"
        ctx.summary["loki_error"] = loki_err
        return corr

    # ranked pods
    ranked = sorted(counts_by_pod.items(), key=lambda kv: kv[1], reverse=True)
    top = ranked[:top_n]
    top_pods = [p for p, c in top if p]

    if not top_pods:
        corr = {"status": "no_loki_pods", "pods": []}
        ctx.summary["correlation"] = corr
        return corr

    # --- 2) Loki samples (每 pod 拉少量样本) ---
    pods_out: List[Dict[str, Any]] = []
    samples_total = 0

    for pod, cnt in top:
        q_s, rows, resp_s = _loki_error_samples_for_pod(settings, pod, limit=5)
        samples_total += len(rows)

        # 统计容器分布
        containers: Dict[str, int] = defaultdict(int)
        for r in rows:
            containers[r.get("container") or "unknown"] += 1

        pods_out.append({
            "pod": pod,
            "loki_error_count": cnt,
            "loki_containers": dict(containers),
            "loki_samples": rows,
            "loki_queries": {
                "sample_query": q_s,
            },
        })

    # --- 3) Prom (你原来的逻辑保持) ---
    prom = build_client(settings)
    pod_re = prom_regex_from_list(top_pods)

    lookback = f"{settings.lookback_minutes}"
    selector = (
        f'namespace="{prom_str(settings.namespace)}",'
        f'pod=~"{pod_re}",'
        f'container="{prom_str(settings.app_label)}"'
    )

    q_restarts_by_pod = (
        "sum by (pod) ("
        f'increase(kube_pod_container_status_restarts_total{{{selector}}}[{lookback}m])'
        ")"
    )

    # CrashLoopBackOff: gauge(0/1) -> 用 max_over_time 看窗口内是否出现过
    selector_wait = (
    f'namespace="{prom_str(settings.namespace)}",'
    f'pod=~"{pod_re}"'
)
    q_crashloop_by_pod = (
        "sum by (pod) ("
        f'max_over_time(kube_pod_container_status_waiting_reason{{{selector_wait},reason="CrashLoopBackOff"}}[{lookback}m])'
        #f'kube_pod_container_status_waiting_reason{{{selector_wait},reason="CrashLoopBackOff"}}'
        ")"
    )

    

    restarts_by_pod = _prom_query_series(prom, q_restarts_by_pod)
    crashloop_by_pod = _prom_query_series(prom, q_crashloop_by_pod)

    # 回填 Prom 数值到 pods_out
    for item in pods_out:
        pod = item["pod"]
        item["prom_restarts_increase"] = restarts_by_pod.get(pod, 0.0)
        item["prom_crashloop_backoff"] = crashloop_by_pod.get(pod, 0.0)

    corr = {
        "status": "ok",
        "top_n": top_n,
        "pod_regex": pod_re,
        "queries": {
            "loki_error_counts_by_pod": q_loki_stats,
            "restarts_by_pod": q_restarts_by_pod,
            "crashloop_by_pod": q_crashloop_by_pod,
        },
        "pods": pods_out,
    }

    ctx.summary["correlation"] = corr

    # ✅ 关键：把“统计值”和“样本数”写进 summary（不再依赖 limit=50 的 rows）
    ctx.summary["error_log_count_window"] = int(sum(counts_by_pod.values()))
    ctx.summary["error_log_sample_count"] = samples_total

    # worst_pod 仍保留
    worst = max(
        pods_out,
        key=lambda x: (x["prom_crashloop_backoff"], x["prom_restarts_increase"], x["loki_error_count"])
    )
    ctx.summary["worst_pod"] = worst.get("pod")
    # after computing worst
    ctx.summary["crashloop_backoff"] = worst.get("prom_crashloop_backoff")
    ctx.summary["worst_pod_crashloop_backoff"] = worst.get("prom_crashloop_backoff")
    ctx.summary["worst_pod_restarts_increase"] = worst.get("prom_restarts_increase")

    return corr