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
    """
    Extract first scalar (vector[0].value[1]) from Prometheus instant query response.
    Returns 0.0 if result is empty; None if unexpected format.
    """
    try:
        result = resp.get("data", {}).get("result", [])
        if not result:
            return 0.0
        return float(result[0]["value"][1])
    except Exception:
        return None


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

    # NOTE: keep PromQL strings pure; do not accidentally '+ 1' in Python.
    promql_restarts = (
        f'sum(increase(kube_pod_container_status_restarts_total{{namespace="{settings.namespace}"}}'
        f'[{settings.lookback_minutes}m]))'
    )
    promql_running_pods = (
        f'count(kube_pod_status_phase{{namespace="{settings.namespace}", phase="Running"}} == 1)'
    )
    
    promql_crashloop = (
        f'sum(kube_pod_container_status_waiting_reason{{namespace="{settings.namespace}", reason="CrashLoopBackOff"}})'
    )
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
    summary["crashloop_backoff"] = crashloop.scalar

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

    prom_queries = {
        "pod_restarts_total": {
            "query": restarts.query,
            "response": restarts.response,
            "scalar": restarts.scalar,
        },
        "running_pods": {
            "query": running.query,
            "response": running.response,
            "scalar": running.scalar,
        },
    }

    summary = {
        "pod_restarts_total": restarts.scalar,
        "running_pods": running.scalar,
    }

    return prom_queries, summary