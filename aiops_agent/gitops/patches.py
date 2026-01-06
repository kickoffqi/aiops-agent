from __future__ import annotations
from typing import Any, Dict, List, Optional
from ..incident import IncidentContext
import yaml

def _deployment_patch_env(name: str, value: str) -> Dict[str, Any]:
    """
    Strategic-merge patch to set env var on first container.
    """
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "flask-demo"},
        "spec": {
            "template": {
                "spec": {
                    "containers": [
                        {
                            "name": "flask-demo",
                            "env": [{"name": name, "value": value}],
                        }
                    ]
                }
            }
        },
    }


def _deployment_patch_remove_env(name: str) -> Dict[str, Any]:
    """
    Strategic merge cannot "remove" env cleanly without full list.
    For GitOps we often patch by setting it to empty or adjusting config.
    Here we set it to "0" for demo.
    """
    return _deployment_patch_env(name, "0")


def _deployment_patch_probes() -> Dict[str, Any]:
    """
    Add basic readiness/liveness probes (HTTP GET /).
    """
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "flask-demo"},
        "spec": {
            "template": {
                "spec": {
                    "containers": [
                        {
                            "name": "flask-demo",
                            "readinessProbe": {
                                "httpGet": {"path": "/", "port": 8080},
                                "initialDelaySeconds": 5,
                                "periodSeconds": 5,
                            },
                            "livenessProbe": {
                                "httpGet": {"path": "/", "port": 8080},
                                "initialDelaySeconds": 20,
                                "periodSeconds": 10,
                            },
                        }
                    ]
                }
            }
        },
    }


def _deployment_patch_resources() -> Dict[str, Any]:
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "flask-demo"},
        "spec": {
            "template": {
                "spec": {
                    "containers": [
                        {
                            "name": "flask-demo",
                            "resources": {
                                "requests": {"cpu": "100m", "memory": "256Mi"},
                                "limits": {"cpu": "1000m", "memory": "768Mi"},
                            },
                        }
                    ]
                }
            }
        },
    }


def generate_gitops_patches(ctx: IncidentContext) -> List[Dict[str, Any]]:
    """
    Generate a list of Kubernetes YAML patches (strategic merge style).
    For now targets the demo Deployment 'flask-demo'.
    """
    s = ctx.summary or {}
    category = s.get("suspected_category")
    patches: List[Dict[str, Any]] = []

    # Baseline: probes are generally useful
    patches.append(_deployment_patch_probes())

    if category == "config":
        patches.append(_deployment_patch_env("REQUIRED_TOKEN", "set-me"))
    elif category == "dependency":
        # In a real app we might patch env for dependency URL + timeouts.
        # Here we add probes/resources as a minimal helpful change.
        patches.append(_deployment_patch_resources())
    elif category == "memory":
        patches.append(_deployment_patch_resources())
    elif category in ("crashloop", "crashloop_or_instability"):
        patches.append(_deployment_patch_remove_env("CRASH_ON_START"))

    return patches


def dump_patches_yaml(patches: List[Dict[str, Any]]) -> str:
    """
    Multi-document YAML, suitable to commit to GitOps repo (overlays/patches).
    """
    return "\n---\n".join([yaml.safe_dump(p, sort_keys=False) for p in patches])