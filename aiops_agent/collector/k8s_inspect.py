from __future__ import annotations
import json
import subprocess
from typing import Any, Dict, List, Optional

from ..incident import IncidentContext
from ..config import Settings

def _run(cmd: List[str]) -> str:
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if p.returncode != 0:
        raise RuntimeError(f"cmd failed: {' '.join(cmd)}\n{p.stderr}")
    return p.stdout

def _kubectl_get(kind: str, name: str, ns: str) -> Dict[str, Any]:
    out = _run(["kubectl", "-n", ns, "get", kind, name, "-o", "json"])
    return json.loads(out)

def _kubectl_events(ns: str, selector: str, tail: int = 50) -> str:
    # describe 输出里包含 probe failed 的 Message，MVP 用它最省事
    return _run(["kubectl", "-n", ns, "describe", "pod", "-l", selector])

def _extract_ports_and_probes_from_deploy(dep: Dict[str, Any]) -> Dict[str, Any]:
    c = dep["spec"]["template"]["spec"]["containers"][0]
    ports = []
    for p in c.get("ports", []) or []:
        ports.append({"name": p.get("name"), "port": p.get("containerPort")})

    def probe_obj(probe: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if not probe:
            return None
        http = (probe.get("httpGet") or {})
        return {
            "path": http.get("path"),
            "port": http.get("port"),
        }

    return {
        "container_ports": ports,
        "probes": {
            "liveness": probe_obj(c.get("livenessProbe")),
            "readiness": probe_obj(c.get("readinessProbe")),
        },
    }

def _extract_service_ports(svc: Dict[str, Any]) -> Dict[str, Any]:
    p = (svc.get("spec", {}).get("ports", []) or [])[0]
    return {"port": p.get("port"), "targetPort": p.get("targetPort"), "name": p.get("name")}

def _extract_endpoints_ports(ep: Dict[str, Any]) -> List[int]:
    ports: List[int] = []
    for subset in ep.get("subsets", []) or []:
        for p in subset.get("ports", []) or []:
            if isinstance(p.get("port"), int):
                ports.append(p["port"])
    return ports

def _probe_fail_lines(describe_text: str, max_lines: int = 8) -> List[str]:
    hits = []
    for line in describe_text.splitlines():
        l = line.lower()
        if "probe failed" in l or "readiness probe" in l or "liveness probe" in l:
            hits.append(line.strip())
    return hits[:max_lines]

def inspect_k8s_ports(ctx: IncidentContext, settings: Settings) -> Dict[str, Any]:
    ns = settings.namespace
    name = settings.app_label  # 你这里的 chart/release/name 都叫 flask-demo

    dep = _kubectl_get("deploy", name, ns)
    svc = _kubectl_get("svc", name, ns)

    k8s = {
        "deployment": _extract_ports_and_probes_from_deploy(dep),
        "service": _extract_service_ports(svc),
        "endpoints": None,
        "pod_events": {"probe_fail_samples": []},
    }

    # endpoints 可能没有（例如 headless / selector 错），容错即可
    try:
        ep = _kubectl_get("endpoints", name, ns)
        k8s["endpoints"] = {"ports": _extract_endpoints_ports(ep)}
    except Exception:
        k8s["endpoints"] = {"ports": []}

    # pod events（基于 service selector：app.kubernetes.io/name=flask-demo,app.kubernetes.io/instance=flask-demo）
    selector = f"app.kubernetes.io/name={name},app.kubernetes.io/instance={name}"
    try:
        desc = _kubectl_events(ns, selector)
        k8s["pod_events"]["probe_fail_samples"] = _probe_fail_lines(desc)
    except Exception:
        pass

    ctx.summary["k8s"] = k8s
    return k8s