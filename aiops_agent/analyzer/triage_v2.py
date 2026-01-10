from __future__ import annotations
import json
from typing import Any, Dict, List, Optional, Tuple
from ..incident import IncidentContext
from .utlis import _num

print("[DBG] triage_incident_v2 called")

def _iter_loki_lines_for_triage(ctx: IncidentContext, max_rows: int = 50) -> List[str]:
    """
    Prefer correlation.worst_pod samples, fallback to global loki error_logs rows.
    Return a list of log lines (strings).
    """
    # 1) Prefer correlation worst_pod samples
    try:
        corr = (ctx.summary or {}).get("correlation") or {}
        worst_pod = (ctx.summary or {}).get("worst_pod")
        pods = corr.get("pods") or []
        if worst_pod and isinstance(pods, list):
            for p in pods:
                if p.get("pod") == worst_pod:
                    samples = p.get("loki_samples") or []
                    lines = [s.get("line", "") for s in samples if isinstance(s, dict)]
                    return [x for x in lines if isinstance(x, str)][:max_rows]
    except Exception:
        pass

    # 2) Fallback: global rows
    try:
        rows = ctx.loki_queries.get("error_logs", {}).get("rows", [])  # type: ignore[assignment]
        lines = [r.get("line", "") for r in rows if isinstance(r, dict)]
        return [x for x in lines if isinstance(x, str)][:max_rows]
    except Exception:
        return []
    

def _corr_worst_pod_signals(ctx: IncidentContext) -> Dict[str, Optional[float]]:
    """
    Pull worst_pod Prom signals from ctx.summary["correlation"] if present.
    Returns: { "worst_pod": str|None, "restarts": float|None, "crashloop": float|None }
    """
    s = ctx.summary or {}
    corr = s.get("correlation") or {}
    worst = s.get("worst_pod")

    if not worst or not isinstance(corr, dict):
        return {"worst_pod": None, "restarts": None, "crashloop": None}

    pods = corr.get("pods") or []
    if not isinstance(pods, list):
        return {"worst_pod": worst, "restarts": None, "crashloop": None}

    for p in pods:
        if isinstance(p, dict) and p.get("pod") == worst:
            return {
                "worst_pod": worst,
                "restarts": _num(p.get("prom_restarts_increase")),
                "crashloop": _num(p.get("prom_crashloop_backoff")),
            }

    return {"worst_pod": worst, "restarts": None, "crashloop": None}

# -------------------------
# Log parsing & heuristics
# -------------------------
def _row_text(r: Dict[str, Any]) -> str:
    # 兼容不同 collector 字段命名：line / log / message
    for k in ("line", "log", "message", "msg"):
        v = r.get(k)
        if isinstance(v, str) and v.strip():
            return v
    return ""

def _extract_json_obj_from_line(line: str) -> Optional[Dict[str, Any]]:
    """
    兼容：'... ERROR xxx {json...}' 这种“行内 JSON”
    """
    if not line:
        return None
    start = line.find("{")
    end = line.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None
    blob = line[start : end + 1].strip()
    if not (blob.startswith("{") and blob.endswith("}")):
        return None
    try:
        obj = json.loads(blob)
        return obj if isinstance(obj, dict) else None
    except Exception:
        return None

def _extract_error_types_from_loki(ctx: IncidentContext, max_rows: int = 200) -> List[str]:
    """
    Parse Loki rows and extract error_type.
    - 支持 line/log/message 字段
    - 支持 行内 JSON
    - 对 gunicorn / crashloop 关键字做 fallback
    """
    try:
        rows = ctx.loki_queries.get("error_logs", {}).get("rows", []) or []
    except Exception:
        rows = []

    types: List[str] = []
    for r in rows[:max_rows]:
        line = _row_text(r)
        l = line.lower()

        # 1) 优先：结构化 JSON（行内 JSON）
        obj = _extract_json_obj_from_line(line)
        if obj:
            et = obj.get("error_type")
            if isinstance(et, str) and et:
                types.append(et)
                continue
        
        # NEW: path-based override if present in raw text
        if 'path":"/unknown"' in l or " /unknown" in l:
            types.append("unknown")
            continue
        
        # 2) fallback heuristics（覆盖 gunicorn/crashloop）
        if "missing required_token" in l or "missing required_token env var" in l or "missing config" in l:
            types.append("config")
        elif "connect failed" in l or "timed out" in l or "connection refused" in l:
            # 你的 /dep 会出现 timed out
            types.append("dependency")
        elif "crash_on_start" in l or "exiting now" in l or "crashloop" in l:
            types.append("crashloop")
        elif "worker failed to boot" in l or "exited with code 42" in l or "reason: worker failed to boot" in l:
            # gunicorn 常见 crashloop 形态
            types.append("crashloop")
        elif "oom" in l or "oomkilled" in l or "memory" in l or "killed process" in l:
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

def _telemetry_ok(ctx: IncidentContext) -> bool:
    s = ctx.summary or {}
    prom_ok = (s.get("prometheus_status") == "ok")
    loki_ok = (s.get("loki_status") == "ok")
    running_pods = _num(s.get("running_pods"))
    corr = s.get("correlation") or {}
    corr_status = corr.get("status")
    has_corr_pods = bool((corr.get("pods") or []))

    # 你可以按你的项目语义微调：
    # - prom/loki ok
    # - running_pods > 0
    # - correlation 至少不是 outright error
    # - 并且最好能选到 pods（否则可能是 selector 问题）
    if not (prom_ok and loki_ok):
        return False
    if running_pods is None or running_pods <= 0:
        return False
    if corr_status in {"loki_error", "prom_error"}:
        return False
    if not has_corr_pods and corr_status == "no_loki_pods":
        return False

    return True
    

def _has_crashloop_signature(ctx: IncidentContext, max_rows: int = 50) -> bool:
    lines = _iter_loki_lines_for_triage(ctx, max_rows=max_rows)
    patterns = [
        "crash_on_start=1",
        "exiting now",
        "worker failed to boot",
        "exited with code 42",
        "crashloopbackoff",
    ]
    for line in lines:
        l = (line or "").lower()
        if any(p in l for p in patterns):
            return True
    return False

def _resolve_named_target_port(container_ports: list, target_port):
    # targetPort 可能是 int 或 "http"
    if isinstance(target_port, int):
        return target_port
    if isinstance(target_port, str):
        for p in container_ports or []:
            if p.get("name") == target_port and isinstance(p.get("port"), int):
                return p["port"]
    return None

def _detect_port_mismatch(ctx: IncidentContext):
    s = ctx.summary or {}
    k8s = s.get("k8s") or {}
    dep = k8s.get("deployment") or {}
    svc = k8s.get("service") or {}
    eps = (k8s.get("endpoints") or {}).get("ports") or []
    events = ((k8s.get("pod_events") or {}).get("probe_fail_samples") or [])

    container_ports = dep.get("container_ports") or []
    container_port_values = [p.get("port") for p in container_ports if isinstance(p.get("port"), int)]
    l_probe = (dep.get("probes") or {}).get("liveness") or {}
    r_probe = (dep.get("probes") or {}).get("readiness") or {}

    probe_ports = [l_probe.get("port"), r_probe.get("port")]
    probe_ports = [p for p in probe_ports if p is not None]

    target_port = svc.get("targetPort")
    resolved_target = _resolve_named_target_port(container_ports, target_port)

    # “强证据”：events 含连接拒绝/超时
    has_probe_fail = any(("connect: connection refused" in (e.lower()))
                         or ("context deadline exceeded" in (e.lower()))
                         for e in events)

    # 不一致判定
    mismatch_reasons = []
    if resolved_target is None and target_port is not None:
        mismatch_reasons.append(f"service.targetPort={target_port} cannot be resolved from container ports")
    if resolved_target is not None and container_port_values and resolved_target not in container_port_values:
        mismatch_reasons.append(
            f"resolved_service_targetPort={resolved_target} not in containerPorts={container_port_values}"
        )
    if resolved_target is not None and probe_ports and any(p != resolved_target for p in probe_ports if isinstance(p, int)):
        mismatch_reasons.append(f"probe.port={probe_ports} != resolved_service_targetPort={resolved_target}")
    if resolved_target is not None and eps and any(ep != resolved_target for ep in eps):
        mismatch_reasons.append(f"endpoints.ports={eps} != resolved_service_targetPort={resolved_target}")

    if mismatch_reasons and (has_probe_fail or len(mismatch_reasons) >= 1):
        return {
            "hit": True,
            "reasons": mismatch_reasons,
            "probe_fail_samples": events[:5],
            "resolved_service_targetPort": resolved_target,
            "container_ports": container_ports,
            "probe_ports": probe_ports,
            "service_targetPort": target_port,
        }
    return {"hit": False}


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
    error_log_count = s.get("error_log_count_window")
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
    corr_sig = _corr_worst_pod_signals(ctx)
    worst_pod = corr_sig["worst_pod"]
    worst_restarts = corr_sig["restarts"]
    worst_crashloop = corr_sig["crashloop"]

    # prefer worst_pod signals if available, else fallback to global namespace signals
    restarts_for_triage = worst_restarts if worst_restarts is not None else pod_restarts_n
    crashloop_for_triage = worst_crashloop if worst_crashloop is not None else crashloop_backoff_n

    is_restarting = restarts_for_triage is not None and restarts_for_triage > 0
    has_backoff = crashloop_for_triage is not None and crashloop_for_triage > 0

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

    pm = _detect_port_mismatch(ctx)
    pm_hit = bool(pm.get("hit"))
    if pm_hit:
        suspected_category = "port_mismatch"
        top_error_type = "port_mismatch"
        triage = "Detected port mismatch between Service targetPort / containerPort / probes, causing probe failures and connection refused."
        recs = [
            "Align containerPort with the actual application listening port",
            "Ensure Service targetPort maps to the correct container port (int or correct named port)",
            "Ensure liveness/readiness probes use the same port as the container listening port",
        ]
        confidence = "high"
        severity = "high" if has_backoff else "medium"
        severity_reason = "port_mismatch_probe_fail"
        # 同时把证据挂到 summary 里，方便 llm_enrich / report.json audit
        ctx.summary["port_mismatch_evidence"] = pm

    # -------------------------
    # Specialization by log type
    # -------------------------
    if not pm_hit and top_error_type == "config":
        suspected_category = "config"
        triage = "Startup or request failures indicate missing or invalid configuration."
        recs = [
            "Validate required environment variables, ConfigMaps, and Secrets",
            "Add startup validation and fail-fast with clear error messages",
            "Patch Deployment via GitOps to set missing env or mount configs",
        ]

    elif not pm_hit and top_error_type == "dependency":
        suspected_category = "dependency"
        triage = "Logs indicate upstream dependency connectivity failures."
        recs = [
            "Check DNS, service endpoints, and network policies",
            "Add timeouts, retries, and circuit-breakers to dependency clients",
            "Ensure readinessProbe depends on critical dependencies",
        ]

    elif not pm_hit and top_error_type == "memory":
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
            # --- NEW: distinguish unknown types ---
            if has_errors and (not is_restarting) and (not has_backoff):
                suspected_category = "unknown"
                triage = (
                    "Application is emitting frequent error logs but there are no restart/crashloop signals. "
                    "This often indicates handler/logic errors, bad requests, or non-fatal exceptions."
                )
                recs = [
                    "Inspect recent error logs for stack traces / request path / error codes",
                    "Check deployment env/config for recent changes (without exposing secrets)",
                    "Correlate with HTTP 5xx rate / request volume if available",
                ]
            else:
                suspected_category = "no_signal"
                triage = "No strong signals (logs/metrics) to classify incident; verify observability pipelines and selectors."
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
    severity_reason = "no_restart_or_crashloop_and_running_pods>0"
    if crashloop_backoff_n is not None and crashloop_backoff_n > 0:
        if pod_restarts_n is not None and pod_restarts_n >= 10:
            severity_reason = "crashloop_backoff>0_and_restarts>=10"
        else:
            severity_reason = "crashloop_backoff>0"
    elif pod_restarts_n is not None and pod_restarts_n > 5:
        severity_reason = "restarts>5"
    elif pod_restarts_n is not None and pod_restarts_n > 0:
        severity_reason = "restarts>0"
    elif running_pods_n is not None and running_pods_n == 0:
        severity_reason = "running_pods==0"

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
            severity_reason = "error_only_no_restart_backoff"

    # 4) healthy：直接给最清晰的结论（可选，但很推荐）
    if suspected_category == "healthy":
        severity = "none"
        severity_reason = "healthy_category"
        confidence = "high" if _telemetry_ok(ctx) else "medium"
        # 或者你更严格： else "unknown"

    dominance = (s.get("dominance_ratio") or 0.0)
    if has_errors and dominance >= 0.6 and confidence in {"low", "unknown"}:
        confidence = "medium"

    if suspected_category == "dependency":
        if error_log_count_n >= 300:
            severity = "high"
            severity_reason = "dependency_error_logs>=300"
            confidence = "high"
        elif error_log_count_n >= 50:
            if severity in {"none", "low"}:
                severity = "medium"
                severity_reason = "dependency_error_logs>=50"
            if confidence in {"unknown", "low", "medium"}:
                confidence = "high"

    err_window = _num(s.get("error_log_count_window")) or error_log_count_n

    if suspected_category in {"config", "dependency"}:
        if err_window >= 300:
            severity = "high"
            severity_reason = "error_logs_window>=300"
        elif err_window >= 50:
            severity = "medium"
            severity_reason = "error_logs_window>=50"
        elif err_window >= 1:
            severity = "low"
            severity_reason = "error_logs_window>=1"
        else:
            severity = "none"
            severity_reason = "error_logs_window==0"
    
    #servity reasons



    # 5) dominance_ratio
    total_err = sum(error_type_counts.values()) if error_type_counts else 0
    dominance = 0.0
    if total_err > 0 and top_error_type:
        dominance = error_type_counts.get(top_error_type, 0) / total_err

    # 6) telemetry confidence
    telemetry_conf = "high" if _telemetry_ok(ctx) else "low"


    # 只用已识别的类型算 dominance（unknown 不算）
    known_counts = {k: v for k, v in error_type_counts.items() if k != "unknown"}
    total_known = sum(known_counts.values())
    if total_known > 0 and top_error_type in known_counts:
        dominance_ratio = known_counts[top_error_type] / total_known
    else:
        dominance_ratio = None

    secondary_error_types = dict(known_counts)
    if top_error_type in secondary_error_types:
        secondary_error_types.pop(top_error_type, None)

    corr = (ctx.summary or {}).get("correlation") or {}
    pods = corr.get("pods") or []

    dominance_ratio_pod = None
    try:
        counts = [float(p.get("loki_error_count", 0.0)) for p in pods]
        total = sum(counts)
        worst = max(counts) if counts else 0.0
        if total > 0:
            dominance_ratio_pod = worst / total
    except Exception:
        dominance_ratio_pod = None

    # keep your existing dominance_ratio as sample-based
    dominance_ratio_sample = dominance_ratio
    if suspected_category == "config":
        if dominance_ratio_sample is not None and dominance_ratio_sample >= 0.6:
            if err_window >= 50:
                confidence = "high"
            elif err_window >= 1 and confidence in {"low","unknown"}:
                confidence = "medium"

    # -------------------------
    # Final Output
    # -------------------------
    triage_obj = {
        "suspected_category": suspected_category,
        "top_error_type": top_error_type,
        "error_type_counts_sampled": error_type_counts,
        "severity": severity,
        "severity_reason": severity_reason,
        "confidence": confidence,
        "triage": triage,
        "recommendations": recs,
        "dominance_ratio_sample": dominance_ratio_sample,
        "dominance_ratio_pod": dominance_ratio_pod,
        "secondary_error_types": secondary_error_types,
        "worst_pod_restarts_increase": restarts_for_triage,
        "worst_pod_crashloop_backoff": crashloop_for_triage,
        "telemetry_confidence": telemetry_conf,
    }

    ctx.summary.update(triage_obj)
    return triage_obj
