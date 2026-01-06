from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from ..prometheus_client import PrometheusClient
from ..config import Settings


@dataclass
class PromQueryResult:
    query: str
    response: Dict[str, Any]
    scalar: Optional[float]


def _first_scalar(resp: Dict[str, Any]) -> Optional[float]:
    try:
        result = resp.get("data", {}).get("result", [])
        if not result:
            return None
        v = result[0].get("value")
        if not v or len(v) < 2:
            return None
        return float(v[1])
    except Exception:
        return None


def _first_int(resp: Dict[str, Any]) -> Optional[int]:
    v = _first_scalar(resp)
    if v is None:
        return None
    if v.is_integer():
        return int(v)
    return int(round(v))


def query_scalar_or_zero(prom, query: str) -> float:
    resp = prom.query(query)
    v = _first_scalar(resp)
    return 0.0 if v is None else v


def query_int_or_zero(prom, query: str) -> int:
    resp = prom.query(query)
    v = _first_int(resp)
    return 0 if v is None else v


def build_client(settings: Settings) -> PrometheusClient:
    """
    Build Prometheus client. For local port-forward, no auth needed.
    If later you expose Prometheus behind auth, extend here.
    """
    return PrometheusClient(
        base_url=settings.prometheus_url,
        headers={},
        auth=None,
        timeout=15,
    )


def collect_namespace_health(settings: Settings) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Collect a small, generic set of signals for a namespace.
    Returns:
      prom_queries: dict[str, {query, response, scalar}]
      summary: dict[str, scalar]
    """
    prom = build_client(settings)

    # ✅ 先初始化容器，后面逐个追加键
    prom_queries: Dict[str, Any] = {}
    summary: Dict[str, Any] = {}
    # selector: namespace + pod prefix + container
    selector = (
        f'namespace="{settings.namespace}", '
        f'pod=~"{settings.app_label}-.*", '
        f'container="{settings.app_label}"'
    )

    # NOTE: keep PromQL strings pure; do not accidentally '+ 1' in Python.
    promql_restarts = (
        f'sum(increase(kube_pod_container_status_restarts_total'
        f'{{{selector}}}[{settings.lookback_minutes}m]))'
    )
    restarts_inc = query_int_or_zero(prom, promql_restarts)

    promql_running_pods = (
        f'count(kube_pod_status_phase{{namespace="{settings.namespace}", phase="Running"}} == 1)'
    )
    promql_crashloop = (
        f'sum(kube_pod_container_status_waiting_reason{{namespace="{settings.namespace}", reason="CrashLoopBackOff"}})'
    )

    # --- CrashLoopBackOff ---
    crashloop_resp = prom.query(promql_crashloop)
    crashloop = PromQueryResult(
        query=promql_crashloop,
        response=crashloop_resp,
        scalar=_first_scalar(crashloop_resp),
    )
    prom_queries["crashloop_backoff"] = {
        "query": crashloop.query,
        "response": crashloop.response,
        "scalar": crashloop.scalar,
    }
    summary["crashloop_backoff"] = _first_int(crashloop_resp)

    # --- restarts / running ---
    restarts_resp = prom.query(promql_restarts)
    running_resp = prom.query(promql_running_pods)

    restarts = PromQueryResult(
        query=promql_restarts,
        response=restarts_resp,
        scalar=_first_scalar(restarts_resp),
    )
    running = PromQueryResult(
        query=promql_running_pods,
        response=running_resp,
        scalar=_first_scalar(running_resp),
    )

    prom_queries["pod_restarts_total"] = {
        "query": restarts.query,
        "response": restarts.response,
        "scalar": restarts.scalar,
    }
    prom_queries["running_pods"] = {
        "query": running.query,
        "response": running.response,
        "scalar": running.scalar,
    }

    summary["pod_restarts_total"] = restarts_inc
    summary["prometheus_status"] = "ok"
    summary["restarts_signal_missing"] = (_first_scalar(prom.query(promql_restarts)) is None)
    #summary["pod_restarts_total"] = restarts.scalar
    summary["running_pods"] = _first_int(running_resp)

    return prom_queries, summary
