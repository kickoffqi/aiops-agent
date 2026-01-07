from __future__ import annotations
import json
from typing import Any
from ..config import Settings
from ..incident import IncidentContext
from ..llm.ollama_client import OllamaClient


SYSTEM_PROMPT = """You are an SRE/AIOps assistant.
Rules:
- Use ONLY the provided evidence. If missing, say "unknown".
- Output MUST be valid JSON.
- Separate safe suggestions from actions that require approval/change control.
"""

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


def enrich_with_llm(ctx: IncidentContext, settings: Settings) -> Dict[str, Any]:
    model = getattr(settings, "ollama_model", "qwen2.5:7b-instruct")
    base_url = getattr(settings, "ollama_url", "http://localhost:11434")
    timeout_s = int(getattr(settings, "ollama_timeout_s", 180))

    client = OllamaClient(base_url=base_url, timeout_s=timeout_s)

    prompt = _build_prompt(ctx)
    out = client.generate_json(model=model, prompt=prompt)

    ctx.summary["llm"] = {
        "status": "ok",
        "provider": "ollama",
        "model": model,
        "system_prompt": SYSTEM_PROMPT,
        "output": out,
    }
    return ctx.summary["llm"]