from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from ..incident import IncidentContext
from ..config import Settings


print("[DBG] remediation_v1 called")

def _as_int(v: Any) -> int:
    try:
        if v is None:
            return 0
        if isinstance(v, bool):
            return int(v)
        if isinstance(v, (int, float)):
            return int(v)
        return int(str(v))
    except Exception:
        return 0


def _as_float(v: Any) -> float:
    try:
        if v is None:
            return 0.0
        if isinstance(v, (int, float)):
            return float(v)
        return float(str(v))
    except Exception:
        return 0.0


def _dedupe(seq: List[str]) -> List[str]:
    seen = set()
    out: List[str] = []
    for x in seq:
        if not x:
            continue
        if x in seen:
            continue
        seen.add(x)
        out.append(x)
    return out


@dataclass
class RemediationPlan:
    status: str  # proposed / not_applicable
    playbook: str
    target: Dict[str, Any]
    rationale: str
    commands: List[str]
    patches: List[Dict[str, Any]]
    verify: List[str]
    safety_notes: List[str]


def _default_target(settings: Settings, ctx: IncidentContext) -> Dict[str, Any]:
    s = ctx.summary or {}
    return {
        "namespace": getattr(settings, "namespace", "default"),
        "app": getattr(settings, "app_label", ""),
        "deployment": getattr(settings, "app_label", ""),  # v1：默认 deployment=app_label
        "worst_pod": s.get("worst_pod"),
    }


def _verify_snippets(settings: Settings, pod_re: Optional[str] = None) -> List[str]:
    ns = getattr(settings, "namespace", "default")
    app = getattr(settings, "app_label", "")
    lookback = getattr(settings, "lookback_minutes", 60)

    # 这里的 verify 是“人类/CI 可执行的检查”，不依赖你的 Prom/Loki client。
    return _dedupe([
        f'kubectl -n {ns} get pods -l app={app} -o wide',
        f'kubectl -n {ns} get events --sort-by=.lastTimestamp | tail -n 50',
        f'kubectl -n {ns} logs -l app={app} --since={lookback}m | tail -n 200',
        # PromQL（你可以直接贴到 Prom UI / Grafana Explore）
        f'PromQL: sum(increase(kube_pod_container_status_restarts_total{{namespace="{ns}"}}[15m]))',
        f'PromQL: sum(kube_pod_container_status_waiting_reason{{namespace="{ns}", reason="CrashLoopBackOff"}})',
        # Loki（Grafana Explore）
        f'Loki: sum(rate({{namespace="{ns}", app="{app}"}} |~ "(?i)error"[5m]))',
        (f'PromQL (by pod): sum by (pod) (increase(kube_pod_container_status_restarts_total{{namespace="{ns}", pod=~"{pod_re or ".*"}"}}[15m]))'
         if pod_re else
         f'PromQL (by pod): sum by (pod) (increase(kube_pod_container_status_restarts_total{{namespace="{ns}"}}[15m]))'),
    ])


def _playbook_crashloop(settings: Settings, ctx: IncidentContext) -> RemediationPlan:
    target = _default_target(settings, ctx)
    ns = target["namespace"]
    deploy = target["deployment"] or target["app"]
    app = target["app"]
    s = ctx.summary or {}
    corr = s.get("correlation") or {}
    pod_re = None
    if isinstance(corr, dict):
        pod_re = corr.get("pod_regex")

    rationale = (
        "Detected CrashLoop pattern (logs + restarts increasing). "
        "Most common immediate cause in this lab is a crash flag/env or startup misconfig."
    )

    commands = [
        # 1) 立刻止血：移除 crash flag
        f"kubectl -n {ns} set env deploy/{deploy} CRASH_ON_START-",
        f"kubectl -n {ns} rollout status deploy/{deploy}",
        # 2) 如果你希望保留但禁用（可选）
        # f"kubectl -n {ns} set env deploy/{deploy} CRASH_ON_START=0",
        # 3) 观察
        f"kubectl -n {ns} get pods -l app={app} -w",
        f"kubectl -n {ns} logs -l app={app} --previous --tail=200",
    ]

    # v1 patch：给出一个“可选”探针 patch（不确定你是否已有 /healthz /readyz）
    patches = [
        {
            "type": "kubectl-json-patch",
            "resource": f"deploy/{deploy}",
            "description": "Add liveness/readiness probes (requires /healthz and /readyz endpoints).",
            "payload": [
                {
                    "op": "add",
                    "path": "/spec/template/spec/containers/0/livenessProbe",
                    "value": {
                        "httpGet": {"path": "/healthz", "port": 5000},
                        "initialDelaySeconds": 10,
                        "periodSeconds": 10,
                        "timeoutSeconds": 2,
                        "failureThreshold": 3,
                    },
                },
                {
                    "op": "add",
                    "path": "/spec/template/spec/containers/0/readinessProbe",
                    "value": {
                        "httpGet": {"path": "/readyz", "port": 5000},
                        "initialDelaySeconds": 5,
                        "periodSeconds": 5,
                        "timeoutSeconds": 2,
                        "failureThreshold": 3,
                    },
                },
            ],
            "apply_example": f"""kubectl -n {ns} patch deploy/{deploy} --type='json' -p='<PAYLOAD>'""",
        }
    ]

    verify = _verify_snippets(settings, pod_re=pod_re)

    safety_notes = [
        "This plan is PROPOSED only; it does not execute changes.",
        "Removing CRASH_ON_START is safe in this lab; in real systems confirm with change control/GitOps.",
        "Probe patch requires the app to expose /healthz and /readyz; otherwise pods may become NotReady.",
    ]

    return RemediationPlan(
        status="proposed",
        playbook="crashloop_env_or_startup",
        target=target,
        rationale=rationale,
        commands=commands,
        patches=patches,
        verify=verify,
        safety_notes=safety_notes,
    )


def _playbook_config(settings: Settings, ctx: IncidentContext) -> RemediationPlan:
    target = _default_target(settings, ctx)
    ns = target["namespace"]
    deploy = target["deployment"] or target["app"]
    app = target["app"]
    s = ctx.summary or {}
    corr = s.get("correlation") or {}
    pod_re = corr.get("pod_regex") if isinstance(corr, dict) else None

    rationale = "Logs indicate missing/invalid configuration (env/ConfigMap/Secret)."

    commands = [
        f"kubectl -n {ns} describe deploy/{deploy} | sed -n '1,200p'",
        f"kubectl -n {ns} get cm,secret -o wide | head -n 50",
        f"kubectl -n {ns} logs -l app={app} --since=60m | tail -n 200",
        # v1: 你可以把 REQUIRED_TOKEN 作为例子（不替你生成真实值）
        f"kubectl -n {ns} set env deploy/{deploy} REQUIRED_TOKEN=<SET_ME>",
        f"kubectl -n {ns} rollout status deploy/{deploy}",
    ]

    patches: List[Dict[str, Any]] = [
        {
            "type": "kubectl-set-env",
            "resource": f"deploy/{deploy}",
            "description": "Set required env vars (example: REQUIRED_TOKEN). Use GitOps in real workflow.",
            "env": {"REQUIRED_TOKEN": "<SET_ME>"},
        }
    ]

    verify = _verify_snippets(settings, pod_re=pod_re)

    safety_notes = [
        "Do NOT put real secrets into shell history; prefer Kubernetes Secret + envFrom/volume.",
        "In real workflow, patch via GitOps (Helm/Kustomize) rather than kubectl set env.",
    ]

    return RemediationPlan(
        status="proposed",
        playbook="missing_config_env",
        target=target,
        rationale=rationale,
        commands=commands,
        patches=patches,
        verify=verify,
        safety_notes=safety_notes,
    )


def _playbook_dependency(settings: Settings, ctx: IncidentContext) -> RemediationPlan:
    target = _default_target(settings, ctx)
    ns = target["namespace"]
    app = target["app"]
    deploy = target["deployment"] or app
    s = ctx.summary or {}
    corr = s.get("correlation") or {}
    pod_re = corr.get("pod_regex") if isinstance(corr, dict) else None

    rationale = "Logs show upstream dependency connectivity failures (DNS/endpoint/network-policy/timeout)."

    commands = [
        f"kubectl -n {ns} get svc,endpoints -o wide",
        f"kubectl -n {ns} get netpol -o wide",
        f"kubectl -n {ns} logs -l app={app} --since=60m | tail -n 200",
        # 如果你有一个 debug pod：
        f"kubectl -n {ns} run netshoot --rm -it --image nicolaka/netshoot -- /bin/bash",
        "# inside netshoot: nslookup <svc>; curl -v <endpoint>; nc -vz <host> <port>",
    ]

    patches = [
        {
            "type": "note",
            "resource": f"deploy/{deploy}",
            "description": "Consider adding readinessProbe that depends on critical dependencies; add timeouts/retries/circuit-breakers in code.",
        }
    ]

    verify = _verify_snippets(settings, pod_re=pod_re)

    safety_notes = [
        "Netshoot is for debugging; remove when done.",
        "If dependency is external, verify AKS outbound rules/NAT/NSG.",
    ]

    return RemediationPlan(
        status="proposed",
        playbook="dependency_connectivity",
        target=target,
        rationale=rationale,
        commands=commands,
        patches=patches,
        verify=verify,
        safety_notes=safety_notes,
    )


def _playbook_memory(settings: Settings, ctx: IncidentContext) -> RemediationPlan:
    target = _default_target(settings, ctx)
    ns = target["namespace"]
    app = target["app"]
    deploy = target["deployment"] or app
    s = ctx.summary or {}
    corr = s.get("correlation") or {}
    pod_re = corr.get("pod_regex") if isinstance(corr, dict) else None

    rationale = "Signals suggest memory pressure / allocation issues (possible OOMKilled)."

    commands = [
        f"kubectl -n {ns} describe pod -l app={app} | sed -n '1,220p'",
        f"kubectl -n {ns} top pod -n {ns} | head -n 30",
        f"kubectl -n {ns} logs -l app={app} --since=60m | tail -n 200",
        f"kubectl -n {ns} logs -l app={app} --previous --tail=200",
        f"kubectl -n {ns} describe pod -l app={app} | sed -n '1,220p'"
    ]

    patches = [
        {
            "type": "kubectl-json-patch",
            "resource": f"deploy/{deploy}",
            "description": "Example: set requests/limits for memory (tune values).",
            "payload": [
                {
                    "op": "add",
                    "path": "/spec/template/spec/containers/0/resources",
                    "value": {
                        "requests": {"cpu": "100m", "memory": "128Mi"},
                        "limits": {"cpu": "500m", "memory": "512Mi"},
                    },
                }
            ],
        }
    ]

    verify = _verify_snippets(settings, pod_re=pod_re)

    safety_notes = [
        "Resource limits need tuning; too low causes throttling/OOM, too high wastes capacity.",
        "If you use HPA/VPA later, align requests with autoscaling strategy.",
    ]

    return RemediationPlan(
        status="proposed",
        playbook="memory_pressure",
        target=target,
        rationale=rationale,
        commands=commands,
        patches=patches,
        verify=verify,
        safety_notes=safety_notes,
    )


def remediation_v1(ctx: IncidentContext, settings: Settings) -> Dict[str, Any]:
    """
    Remediation v1: proposes a playbook + commands + optional patches.
    Does NOT execute anything.
    """
    s = ctx.summary or {}
    suspected = (s.get("suspected_category") or "unknown").lower()
    top_error_type = (s.get("top_error_type") or "unknown").lower()

    # 你现在 summary 里也有 dominance（样本/Pod），可以用于“是否值得自动建议”
    dom_pod = _as_float(s.get("dominance_ratio_pod"))
    dom_sample = _as_float(s.get("dominance_ratio_sample"))
    restarts = _as_int(s.get("pod_restarts_total"))
    has_errors = _as_int(s.get("error_log_count")) > 0

    # 简单 gate：如果完全没信号，就不提 remediation
    if (not has_errors) and restarts == 0:
        plan = RemediationPlan(
            status="not_applicable",
            playbook="none",
            target=_default_target(settings, ctx),
            rationale="No error logs and no restart signals; remediation not applicable.",
            commands=[],
            patches=[],
            verify=_verify_snippets(settings),
            safety_notes=["No action required."],
        )
    else:
        # 选择 playbook：优先用 suspected_category；否则用 top_error_type
        key = suspected if suspected != "unknown" else top_error_type

        if key == "crashloop":
            plan = _playbook_crashloop(settings, ctx)
        elif key == "config":
            plan = _playbook_config(settings, ctx)
        elif key == "dependency":
            plan = _playbook_dependency(settings, ctx)
        elif key == "memory":
            plan = _playbook_memory(settings, ctx)
        else:
            plan = RemediationPlan(
                status="proposed",
                playbook="generic_triage",
                target=_default_target(settings, ctx),
                rationale="Incident detected but category is unclear; propose generic triage steps.",
                commands=_dedupe([
                    f'kubectl -n {settings.namespace} get pods -o wide',
                    f'kubectl -n {settings.namespace} get events --sort-by=.lastTimestamp | tail -n 50',
                    f'kubectl -n {settings.namespace} logs -l app={settings.app_label} --since={getattr(settings,"lookback_minutes",60)}m | tail -n 200',
                ]),
                patches=[],
                verify=_verify_snippets(settings),
                safety_notes=["Use GitOps for persistent changes."],
            )

    # 增强：把 dominance/restarts 作为“自动化建议强度”
    automation_hint = "manual"
    if plan.status == "proposed":
        if dom_pod >= 0.90 and restarts >= 3:
            automation_hint = "safe_to_auto_suggest"
        elif dom_sample >= 0.85:
            automation_hint = "suggest"
        else:
            automation_hint = "manual"
    
    expected_outcomes = [
    "Pod restarts should stop increasing within 5-10 minutes",
    "CrashLoopBackOff waiting reason should be 0 for worst pod",
    "Error log rate should drop significantly"
    ]

    success_criteria = [
    "PromQL: sum(increase(kube_pod_container_status_restarts_total{namespace=\"default\"}[10m])) == 0",
    "PromQL: max_over_time(kube_pod_container_status_waiting_reason{namespace=\"default\",reason=\"CrashLoopBackOff\",pod=~\"<pod_re>\"}[10m]) == 0",
    "Loki: sum(rate({namespace=\"default\",app=\"flask-demo\"} |~ \"(?i)error\"[5m])) near 0"
    ]

    rollback = [
    "If change applied via kubectl set env, revert by redeploying previous revision or GitOps revert",
    "kubectl -n default rollout undo deploy/flask-demo"
    ]

    out = {
        "status": plan.status,
        "playbook": plan.playbook,
        "target": plan.target,
        "rationale": plan.rationale,
        "commands": plan.commands,
        "patches": plan.patches,
        "verify": plan.verify,
        "safety_notes": plan.safety_notes,
        "automation_hint": automation_hint,
        "expected_outcomes": expected_outcomes,
        "success_criteria": success_criteria,
        "rollback": rollback,
        "inputs": {
            "suspected_category": suspected,
            "top_error_type": top_error_type,
            "dominance_ratio_pod": dom_pod,
            "dominance_ratio_sample": dom_sample,
            "pod_restarts_total": restarts,
        },
    }

    ctx.summary["remediation"] = out
    return out