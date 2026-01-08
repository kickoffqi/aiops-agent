from __future__ import annotations
import json
import time
from ..config import Settings
from ..incident import IncidentContext
from ..llm.ollama_client import OllamaClient
from ..llm.schema import LLMOutput
from typing import Any, Dict, Optional
import requests


SYSTEM_PROMPT = """You are an SRE/AIOps assistant.
Rules:
- Use ONLY the provided evidence. If missing, say "unknown".
- Output MUST be valid JSON.
- Separate safe suggestions from actions that require approval/change control.
"""
def parse_llm_output(raw_json: dict) -> LLMOutput:
    return LLMOutput(**raw_json)

def _build_prompt(ctx: IncidentContext) -> str:
    summary = ctx.summary or {}
    corr = summary.get("correlation") or {}
    remediation = summary.get("remediation") or {}

    # 只给 LLM 最关键字段，避免 prompt 过长导致慢/超时
    llm_input = {
        "summary": {
            "status": summary.get("status"),
            "pod_restarts_total": summary.get("pod_restarts_total"),
            "running_pods": summary.get("running_pods"),
            "crashloop_backoff": summary.get("crashloop_backoff"),
            "error_log_count": summary.get("error_log_count"),
            "worst_pod": summary.get("worst_pod"),
            "suspected_category": summary.get("suspected_category"),
            "severity": summary.get("severity"),
            "confidence": summary.get("confidence"),
        },
        "pods": [],
        "remediation": remediation,
    }

    for p in (corr.get("pods") or [])[:5]:
        llm_input["pods"].append({
            "pod": p.get("pod"),
            "loki_error_count": p.get("loki_error_count"),
            "prom_restarts_increase": p.get("prom_restarts_increase"),
            "prom_crashloop_backoff": p.get("prom_crashloop_backoff"),
            "loki_samples": (p.get("loki_samples") or [])[:5],
        })

    instruction = (
        "你是AIOps助手。你必须只输出JSON，不能输出任何多余文字。\n"
        "输出schema:\n"
        "{\n"
        '  "llm_summary": {"root_cause": string, "key_evidence": [string], "next_actions": [string]},\n'
        '  "risk_notes": [string],\n'
        '  "confidence": "low"|"medium"|"high"\n'
        "}\n"
    )
    return instruction + "\nINPUT_JSON:\n" + json.dumps(llm_input, ensure_ascii=False)

def fallback_from_summary(ctx):
    s = ctx.summary
    ctx.summary["llm"] = {
        "status": "fallback",
        "provider": "local",
        "output": {
            "llm_summary": {
                "root_cause": s.get("suspected_category", "unknown"),
                "key_evidence": [
                    f"error_log_count: {s.get('error_log_count')}",
                    f"pod_restarts_total: {s.get('pod_restarts_total')}",
                    f"crashloop_backoff: {s.get('crashloop_backoff')}",
                ],
                "next_actions": s.get("recommendations", []),
            },
            "risk_notes": ["LLM unavailable; using rule-based fallback"],
            "confidence": "low",
        },
    }

def build_input_digest(ctx, max_logs: int = 5):
    """
    Build a compact, auditable digest of what we actually send to the LLM.
    This is for debugging, reproducibility, and future evaluation.
    """

    s = ctx.summary or {}
    corr = s.get("correlation", {}) or {}

    # --- Extract a few log samples (worst pod preferred) ---
    samples = []
    try:
        pods = corr.get("pods", []) or []
        worst_pod = s.get("worst_pod")

        # Prefer worst pod samples if available
        target_pods = []
        if worst_pod:
            target_pods = [p for p in pods if p.get("pod") == worst_pod]
        if not target_pods:
            target_pods = pods[:1]

        for p in target_pods:
            for r in p.get("loki_samples", [])[:max_logs]:
                samples.append({
                    "ts": r.get("ts"),
                    "line": r.get("line"),
                })
    except Exception:
        pass

    digest = {
        "suspected_category": s.get("suspected_category"),
        "top_error_type": s.get("top_error_type"),
        "severity": s.get("severity"),
        "confidence": s.get("confidence"),
        "dominance_ratio_pod": s.get("dominance_ratio_pod"),
        "dominance_ratio_sample": s.get("dominance_ratio_sample"),
        "pod_restarts_total": s.get("pod_restarts_total"),
        "crashloop_backoff": s.get("crashloop_backoff"),
        "running_pods": s.get("running_pods"),
        "worst_pod": s.get("worst_pod"),
        "error_log_count": s.get("error_log_count"),
        "sample_logs": samples,
    }

    return digest

def enrich_with_llm(ctx: IncidentContext, settings: Settings) -> Dict[str, Any]:
    model = getattr(settings, "ollama_model", "qwen2.5:7b-instruct")
    base_url = getattr(settings, "ollama_url", "http://localhost:11434")
    timeout_s = int(getattr(settings, "ollama_timeout_s", 180))

    client = OllamaClient(base_url=base_url, timeout_s=timeout_s)

    prompt = _build_prompt(ctx)    

    if not settings.enable_llm:
        ctx.summary["llm"] = {"status": "skipped"}
        return

    start = time.time()
    try:
        raw = client.generate_json(model=model, prompt=prompt)
        parsed = parse_llm_output(raw)
        ctx.summary["llm"] = {
            "status": "ok",
            "provider": "ollama",
            "model": model,
            "latency_ms": int((time.time() - start) * 1000),
            "system_prompt": SYSTEM_PROMPT,
            "input_digest": build_input_digest(ctx),
            "output": parsed.model_dump(),
            "error": None,
        }

    except TimeoutError:
        ctx.summary["llm"] = {
            "status": "timeout",
            "provider": "ollama",
            "model": model,
            "error": "LLM call timed out",
        }
        fallback_from_summary(ctx)

    except Exception as e:
        ctx.summary["llm"] = {
            "status": "error",
            "provider": "ollama",
            "model": model,
            "error": str(e),
        }
        fallback_from_summary(ctx)

    return ctx.summary["llm"]