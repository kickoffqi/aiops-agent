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


# -------------------------
# Helpers
# -------------------------
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
    if float(v).is_integer():
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
    """
    return PrometheusClient(
        base_url=settings.prometheus_url,
        headers={},
        auth=None,
        timeout=15,
    )


# -------------------------
# Main Collector
# -------------------------
def collect_namespace_health_v2(settings: Settings) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Collect a small, generic set of signals for a namespace/app.
    Returns:
      prom_queries: dict[str, {query, response, scalar}]
      summary: dict[str, scalar]
    """
    prom = build_client(settings)

    prom_queries: Dict[str, Any] = {}
    summary: Dict[str, Any] = {}

    # Target selector: namespace + app (by pod prefix & container)
    selector = (
        f'namespace="{settings.namespace}", '
        f'pod=~"{settings.app_label}-.*", '
        f'container="{settings.app_label}"'
    )

    # -------------------------
    # PromQL
    # -------------------------
    promql_restarts = (
        f'sum(increase(kube_pod_container_status_restarts_total'
        f'{{{selector}}}[{settings.lookback_minutes}m]))'
    )

    promql_running_pods = (
        f'count(kube_pod_status_phase{{namespace="{settings.namespace}", '
        f'pod=~"{settings.app_label}-.*", phase="Running"}} == 1)'
    )

    promql_crashloop = (
        f'sum(kube_pod_container_status_waiting_reason'
        f'{{namespace="{settings.namespace}", pod=~"{settings.app_label}-.*", '
        f'reason="CrashLoopBackOff"}})'
    )

    # -------------------------
    # Query once
    # -------------------------
    restarts_resp = prom.query(promql_restarts)
    running_resp = prom.query(promql_running_pods)
    crashloop_resp = prom.query(promql_crashloop)

    # -------------------------
    # Parse results
    # -------------------------
    restarts_scalar = _first_scalar(restarts_resp)
    running_scalar = _first_scalar(running_resp)
    crashloop_scalar = _first_scalar(crashloop_resp)

    # Store raw queries
    prom_queries["pod_restarts_total"] = {
        "query": promql_restarts,
        "response": restarts_resp,
        "scalar": restarts_scalar,
    }
    prom_queries["running_pods"] = {
        "query": promql_running_pods,
        "response": running_resp,
        "scalar": running_scalar,
    }
    prom_queries["crashloop_backoff"] = {
        "query": promql_crashloop,
        "response": crashloop_resp,
        "scalar": crashloop_scalar,
    }

    # -------------------------
    # Summary (typed & stable)
    # -------------------------
    summary["pod_restarts_total"] = _first_int(restarts_resp)
    summary["running_pods"] = _first_int(running_resp)
    summary["crashloop_backoff"] = _first_int(crashloop_resp)

    summary["prometheus_status"] = "ok"

    # Signal missing = metric truly absent, NOT value==0
    summary["restarts_signal_missing"] = (restarts_scalar is None)

    return prom_queries, summary