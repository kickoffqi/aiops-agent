from __future__ import annotations
import json
from typing import Any, Dict, List, Optional, Tuple
from ..incident import IncidentContext
from .utlis import _num 


def _extract_error_types_from_loki(ctx: IncidentContext, max_rows: int = 50) -> List[str]:
    """
    Parse loki_queries.error_logs.rows[*].line and extract error_type from JSON logs, if present.
    Falls back to keyword heuristics if not JSON.
    """
    rows = []
    try:
        rows = ctx.loki_queries.get("error_logs", {}).get("rows", [])  # type: ignore[assignment]
    except Exception:
        rows = []

    types: List[str] = []
    for r in rows[:max_rows]:
        line = r.get("line", "")
        # Many of our demo logs are JSON strings; try parse
        s = line.strip()
        if s.startswith("{") and s.endswith("}"):
            try:
                obj = json.loads(s)
                et = obj.get("error_type")
                if isinstance(et, str) and et:
                    types.append(et)
                    continue
            except Exception:
                pass

        # Fallback heuristics
        l = line.lower()
        if "missing required_token" in l or "missing config" in l:
            types.append("config")
        elif "connect failed" in l or "dependency" in l:
            types.append("dependency")
        elif "crash_on_start" in l or "exiting now" in l or "crashloop" in l:
            types.append("crashloop")
        elif "oom" in l or "memory" in l:
            types.append("memory")
        else:
            types.append("unknown")

    return types


def _top(items: List[str]) -> Tuple[Optional[str], Dict[str, int]]:
    counts: Dict[str, int] = {}
    for x in items:
        counts[x] = counts.get(x, 0) + 1
    if not counts:
        return None, {}
    top_item = max(counts.items(), key=lambda kv: kv[1])[0]
    return top_item, counts


def triage_incident(ctx: IncidentContext) -> Dict[str, Any]:
    """
    Add high-signal triage fields + recommendations to ctx.summary.
    Returns the triage dict for convenience.
    """
    s = ctx.summary or {}

    # inputs
    error_log_count = s.get("error_log_count")
    pod_restarts = s.get("pod_restarts_total")
    running_pods = s.get("running_pods")
    crashloop_backoff = s.get("crashloop_backoff")
    crashloop_backoff_n = _num(crashloop_backoff)

    error_log_count_n = int(error_log_count) if isinstance(error_log_count, (int, float)) else None
    pod_restarts_n = _num(pod_restarts)
    running_pods_n = _num(running_pods)

    error_types = _extract_error_types_from_loki(ctx)
    # Prefer known types when available (avoid unknown dominating)
    known = [t for t in error_types if t != "unknown"]
    top_error_type, error_type_counts = _top(known if known else error_types)

    suspected_category = "unknown"
    triage = ""
    recs: List[str] = []

    # Rule-based classification (v1)
    if error_log_count_n and error_log_count_n > 0:
        # errors exist
        if pod_restarts_n is not None and pod_restarts_n > 0:
            suspected_category = "crashloop_or_instability"
            triage = "Errors detected and pod restarts increased; likely crash-loop or unstable process."
            recs += [
                "Check pod status/events: kubectl get pods; kubectl describe pod; kubectl get events --sort-by=.lastTimestamp",
                "Inspect container exit reason (OOMKilled / CrashLoopBackOff) and tune resources or fix startup failure",
                "Review liveness/readiness probes to avoid premature restarts",
            ]
        elif running_pods_n is not None and running_pods_n == 0:
            suspected_category = "availability"
            triage = "No running pods detected for target app/namespace; likely scheduling/rollout failure."
            recs += [
                "Check deployment/replicas: kubectl get deploy,rs,pods -l app=<app>",
                "Check image pull / node capacity / taints: kubectl describe pod",
                "Roll back last change if needed (GitOps revert)",
            ]
        else:
            # running pods and errors, but not restarting => application/dep/config
            suspected_category = "app_error"
            triage = "Errors detected without restarts; likely application logic, config, or dependency issue."
            recs += [
                "Inspect recent rollout and config changes (ConfigMap/Secret/Deployment image tag)",
                "Check upstream dependencies (DB/API/DNS) and timeouts",
                "Add alerts: error log rate and HTTP 5xx rate; ensure /healthz and readinessProbe are meaningful",
            ]
    else:
        suspected_category = "healthy_or_no_signal"
        triage = "No ERROR logs detected in this time window; system likely healthy or signals are not ingested."
        recs += [
            "Verify promtail is collecting app logs and labels are correct",
            "Verify app emits structured logs and Prometheus metrics",
        ]

    # Specialize based on top_error_type from logs
    if top_error_type in {"config", "dependency", "crashloop", "memory"}:
        suspected_category = top_error_type
        if top_error_type == "config":
            triage = "Errors indicate missing/invalid configuration (e.g., REQUIRED_TOKEN missing)."
            recs = [
                "Validate required env vars / ConfigMap / Secret references",
                "Add startup validation and fail-fast with clear error message",
                "Use GitOps to patch Deployment env and add config checks",
            ]
        elif top_error_type == "dependency":
            triage = "Errors indicate upstream dependency connectivity failures."
            recs = [
                "Check DNS/service endpoints and network policies; verify dependency is reachable from cluster",
                "Add timeouts/retries/circuit-breaker in app client",
                "Add readinessProbe that depends on critical dependencies, so traffic is held until ready",
            ]
        elif top_error_type == "crashloop":
            triage = "Logs indicate crash on start / immediate exit; expect CrashLoopBackOff."
            recs = [
                "Inspect container command/env; remove crash flags; check missing files/secrets",
                "Check events and exit codes; add liveness/readiness probes carefully",
                "Roll back last deployment if needed (GitOps revert)",
            ]
        elif top_error_type == "memory":
            triage = "Logs suggest memory pressure or allocation issues."
            recs = [
                "Check for OOMKilled in pod events; increase memory limit or reduce workload",
                "Add resource requests/limits and consider HPA/VPA for autoscaling",
                "Profile memory usage and cap allocations",
            ]

    if crashloop_backoff_n is not None and crashloop_backoff_n > 0:
        suspected_category = "crashloop"
        triage = "CrashLoopBackOff detected (kube-state-metrics); container is repeatedly failing to start."
        recs = [
            "Check container logs and previous logs: kubectl logs --previous -l app=<app>",
            "Inspect pod events and termination reasons: kubectl describe pod; kubectl get events --sort-by=.lastTimestamp",
            "Validate startup config/secrets and command/args; roll back last change if needed",
        ]

    triage_obj = {
        "suspected_category": suspected_category,
        "top_error_type": top_error_type,
        "error_type_counts": error_type_counts,
        "triage": triage,
        "recommendations": recs,
    }

    # write back into ctx.summary
    ctx.summary.update(triage_obj)
    return triage_obj