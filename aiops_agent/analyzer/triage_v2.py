from __future__ import annotations
import json
from typing import Any, Dict, List, Optional, Tuple
from ..incident import IncidentContext
from .utlis import _num


# -------------------------
# Log parsing & heuristics
# -------------------------
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
        s = line.strip()

        # JSON structured logs
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


# -------------------------
# Severity & Confidence
# -------------------------
def _classify_severity(
    restarts: Optional[float],
    crashloop_backoff: Optional[float],
    running_pods: Optional[float],
) -> str:
    """
    Classify incident severity based on metrics.
    """
    if crashloop_backoff is not None and crashloop_backoff > 0:
        if restarts is not None and restarts >= 10:
            return "critical"
        return "high"

    if restarts is not None and restarts > 5:
        return "high"
    if restarts is not None and restarts > 0:
        return "medium"

    if running_pods is not None and running_pods == 0:
        return "critical"

    return "none"


def _confidence_from_signals(
    has_logs: bool,
    restarts: Optional[float],
    crashloop_backoff: Optional[float],
) -> str:
    """
    Estimate confidence level based on signal convergence.
    """
    signals = 0
    if has_logs:
        signals += 1
    if restarts is not None and restarts > 0:
        signals += 1
    if crashloop_backoff is not None and crashloop_backoff > 0:
        signals += 1

    if signals >= 3:
        return "high"
    if signals == 2:
        return "medium"
    if signals == 1:
        return "low"
    return "unknown"


def _has_crashloop_signature(ctx: IncidentContext, max_rows: int = 50) -> bool:
    rows = []
    try:
        rows = ctx.loki_queries.get("error_logs", {}).get("rows", [])
    except Exception:
        return False

    patterns = [
        "crash_on_start=1",
        "exiting now",
        "worker failed to boot",
        "exited with code 42",
        "crashloopbackoff",
    ]

    for r in rows[:max_rows]:
        line = (r.get("line") or "").lower()
        if any(p in line for p in patterns):
            return True
    return False


def _confidence_from_signals(
    has_logs: bool,
    restarts: Optional[float],
    crashloop_backoff: Optional[float],
) -> str:
    signals = 0
    if has_logs:
        signals += 1
    if restarts is not None and restarts > 0:
        signals += 1
    if crashloop_backoff is not None and crashloop_backoff > 0:
        signals += 1

    if signals >= 3:
        return "high"
    if signals == 2:
        return "medium"
    if signals == 1:
        return "low"
    return "unknown"

def _has_crashloop_signature(ctx: IncidentContext, max_rows: int = 50) -> bool:
    rows = []
    try:
        rows = ctx.loki_queries.get("error_logs", {}).get("rows", [])
    except Exception:
        return False

    patterns = [
        "crash_on_start=1",
        "exiting now",
        "worker failed to boot",
        "exited with code 42",
        "crashloopbackoff",
    ]

    for r in rows[:max_rows]:
        line = (r.get("line") or "").lower()
        if any(p in line for p in patterns):
            return True
    return False

# -------------------------
# Main triage engine
# -------------------------
def triage_incident_v2(ctx: IncidentContext) -> Dict[str, Any]:
    """
    CrashLoop Expert System v2
    Combines:
      - Loki logs
      - Prometheus restarts
      - kube-state-metrics CrashLoopBackOff
    Adds:
      - severity
      - confidence
    """
    s = ctx.summary or {}

    # Inputs
    error_log_count = s.get("error_log_count")
    pod_restarts = s.get("pod_restarts_total")
    running_pods = s.get("running_pods")
    crashloop_backoff = s.get("crashloop_backoff")

    error_log_count_n = int(error_log_count) if isinstance(error_log_count, (int, float)) else 0
    pod_restarts_n = _num(pod_restarts)
    running_pods_n = _num(running_pods)
    crashloop_backoff_n = _num(crashloop_backoff)

    # Loki error classification
    error_types = _extract_error_types_from_loki(ctx)
    known = [t for t in error_types if t != "unknown"]
    top_error_type, error_type_counts = _top(known if known else error_types)

    # Base labels
    suspected_category = "unknown"
    triage = ""
    recs: List[str] = []

    # -------------------------
    # Expert Rules: CrashLoop
    # -------------------------
    is_restarting = pod_restarts_n is not None and pod_restarts_n > 0
    has_backoff = crashloop_backoff_n is not None and crashloop_backoff_n > 0
    has_errors = error_log_count_n > 0

    crash_sig = _has_crashloop_signature(ctx)
    confidence = _confidence_from_signals(
        has_logs=has_errors,
        restarts=pod_restarts_n,
        crashloop_backoff=crashloop_backoff_n,
    )
    # 如果 logs 里已经命中 crashloop 强特征：直接抬高一档
    if crash_sig and confidence in {"low", "medium"}:
        confidence = "high"

    if has_errors and is_restarting:
        suspected_category = "crashloop"
        triage = (
            "Application is repeatedly crashing: error logs present and container restarts are increasing. "
            "This matches Kubernetes CrashLoop behavior."
        )
        recs = [
            "Check container logs (current and previous): kubectl logs <pod>; kubectl logs --previous <pod>",
            "Inspect pod events and termination reasons: kubectl describe pod; kubectl get events --sort-by=.lastTimestamp",
            "Validate startup config/secrets and command/args; remove crash flags or missing env",
            "Roll back last deployment if needed (GitOps revert)",
        ]

    # kube-state-metrics signal: CrashLoopBackOff
    if has_backoff:
        suspected_category = "crashloop"
        triage = (
            "CrashLoopBackOff detected by kube-state-metrics; container fails during startup and is in restart backoff."
        )
        recs = [
            "Inspect previous container logs: kubectl logs --previous -l app=<app>",
            "Check exit codes and pod events: kubectl describe pod",
            "Verify entrypoint/args, secrets, and required environment variables",
            "Rollback last deployment if recent change triggered the failure",
        ]

    # -------------------------
    # Specialization by log type
    # -------------------------
    if top_error_type == "config":
        suspected_category = "config"
        triage = "Startup or request failures indicate missing or invalid configuration."
        recs = [
            "Validate required environment variables, ConfigMaps, and Secrets",
            "Add startup validation and fail-fast with clear error messages",
            "Patch Deployment via GitOps to set missing env or mount configs",
        ]

    elif top_error_type == "dependency":
        suspected_category = "dependency"
        triage = "Logs indicate upstream dependency connectivity failures."
        recs = [
            "Check DNS, service endpoints, and network policies",
            "Add timeouts, retries, and circuit-breakers to dependency clients",
            "Ensure readinessProbe depends on critical dependencies",
        ]

    elif top_error_type == "memory":
        suspected_category = "memory"
        triage = "Logs suggest memory pressure or allocation issues."
        recs = [
            "Check for OOMKilled events: kubectl describe pod",
            "Increase memory limits or reduce workload",
            "Add resource requests/limits and consider HPA/VPA",
        ]

    # Healthy / No-signal fallback (Expert default)
    if not triage:
        if (running_pods_n is not None and running_pods_n > 0) and (not has_errors) and (not is_restarting) and (not has_backoff):
            suspected_category = "healthy"
            triage = "No error logs and no restart signals detected in this time window; workload appears healthy."
            recs = [
                "Optional: add SLO-style signals (HTTP 5xx rate, latency p95/p99) to detect silent failures",
                "Ensure log labels are stable (namespace/app/pod/container) and Prometheus scrape targets are up",
            ]
        
        else:
            suspected_category = "no_signal_or_unknown"
            triage = "No strong signals to classify incident; verify observability pipelines (Prometheus/Loki) and label selectors."
            recs = [
                "Verify Loki selector matches your workload labels (namespace/app/container)",
                "Verify Prometheus is scraping kube-state-metrics and your targets",
            ]

    # -------------------------
    # Severity & Confidence (finalize once)
    # -------------------------
    severity = _classify_severity(
        restarts=pod_restarts_n,
        crashloop_backoff=crashloop_backoff_n,
        running_pods=running_pods_n,
    )

    confidence = _confidence_from_signals(
        has_logs=has_errors,
        restarts=pod_restarts_n,
        crashloop_backoff=crashloop_backoff_n,
    )

    # 1) 如果 Loki 命中 crashloop 强特征：置信度至少 high
    if crash_sig and confidence in {"low", "medium", "unknown"}:
        confidence = "high"

    # 2) 结构化 error_type 命中：至少 medium（即使没有重启）
    if top_error_type in {"config", "dependency", "memory", "crashloop"}:
        if confidence in {"low", "unknown"}:
            confidence = "medium"

    # 3) “error-only” 事件：severity 至少 low（否则会出现你现在这种 none）
    if has_errors and (not is_restarting) and (not has_backoff):
        if severity == "none":
            severity = "low"

    # 4) healthy：直接给最清晰的结论（可选，但很推荐）
    if suspected_category == "healthy":
        severity = "none"
        confidence = "high"

    # -------------------------
    # Final Output
    # -------------------------
    triage_obj = {
        "suspected_category": suspected_category,
        "top_error_type": top_error_type,
        "error_type_counts": error_type_counts,
        "severity": severity,
        "confidence": confidence,
        "triage": triage,
        "recommendations": recs,
    }

    ctx.summary.update(triage_obj)
    return triage_obj