from __future__ import annotations
import json
import time
from ..config import Settings
from ..incident import IncidentContext
from ..llm.ollama_client import OllamaClient
from ..llm.schema import LLMOutput
from typing import Any, Dict, List
import requests

print("[DBG] LLM Enrich called")

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

    # Build evidence pool
    evidence_pool = []

    # metrics evidence (verbatim strings you generate)
    if summary.get("error_log_count_window") is not None:
        evidence_pool.append(f"error_log_count_window: {summary.get('error_log_count_window')}")
    if summary.get("pod_restarts_total") is not None:
        evidence_pool.append(f"pod_restarts_total: {summary.get('pod_restarts_total')}")
    if summary.get("crashloop_backoff") is not None:
        evidence_pool.append(f"crashloop_backoff: {summary.get('crashloop_backoff')}")
    if summary.get("worst_pod"):
        evidence_pool.append(f"worst_pod: {summary.get('worst_pod')}")

    # log evidence (verbatim lines)
    for p in (corr.get("pods") or [])[:1]:
        for r in (p.get("loki_samples") or [])[:5]:
            line = r.get("line")
            if line:
                evidence_pool.append(line)


    # 只给 LLM 最关键字段，避免 prompt 过长导致慢/超时
    llm_input = {
        "summary": {
            "status": summary.get("status"),
            "pod_restarts_total": summary.get("pod_restarts_total"),
            "running_pods": summary.get("running_pods"),
            "crashloop_backoff": summary.get("crashloop_backoff"),
            "error_log_count_window": summary.get("error_log_count_window"),
            "worst_pod": summary.get("worst_pod"),
            "suspected_category": summary.get("suspected_category"),
            "severity": summary.get("severity"),
            "confidence": summary.get("confidence"),
        },
        "pods": [],
        "remediation": remediation,
        "evidence_pool": evidence_pool[:12],
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
        "You are an AIOps incident assistant.\n"
        "Task:\n"
        "1) Summarize the incident for an on-call engineer.\n"
        "2) Provide 1-3 hypotheses with evidence strictly from the input.\n"
        "3) next_actions MUST be a subset of remediation.commands and remediation.verify; copy verbatim. Do not paraphrase.\n"
        "4) key_evidence MUST be a subset of evidence_pool; copy verbatim. Do not paraphrase.\n"
        "Export Schema:\n"
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

def _select_actions_from_remediation(ctx: IncidentContext, max_actions: int = 5) -> List[str]:
    """
    Enforce: next_actions MUST be subset of remediation.commands and remediation.verify; copy verbatim.
    """
    s = ctx.summary or {}
    rem = (s.get("remediation") or {}) if isinstance(s.get("remediation"), dict) else {}

    commands = rem.get("commands") or []
    verify = rem.get("verify") or []

    actions: List[str] = []
    if isinstance(commands, list):
        actions.extend([x for x in commands if isinstance(x, str) and x.strip()])
    if isinstance(verify, list):
        actions.extend([x for x in verify if isinstance(x, str) and x.strip()])

    # last-resort fallback (only if remediation is missing)
    if not actions:
        recs = s.get("recommendations") or []
        if isinstance(recs, list):
            actions = [x for x in recs if isinstance(x, str) and x.strip()]

    return actions[:max_actions]


def fallback_output_from_ctx(ctx: IncidentContext, reason: str) -> Dict[str, Any]:
    """
    Always return a dict that matches LLMOutput schema.
    """
    s = ctx.summary or {}

    # Build evidence lines from existing signals (keep it short and auditable)
    evidence: List[str] = []
    if s.get("suspected_category") is not None:
        evidence.append(f"suspected_category: {s.get('suspected_category')}")
    if s.get("top_error_type") is not None:
        evidence.append(f"top_error_type: {s.get('top_error_type')}")
    if s.get("severity") is not None:
        evidence.append(f"severity: {s.get('severity')}")
    if s.get("error_log_count_window") is not None:
        evidence.append(f"error_log_count_window: {s.get('error_log_count_window')}")
    elif s.get("error_log_count") is not None:
        evidence.append(f"error_log_count: {s.get('error_log_count')}")
    if s.get("pod_restarts_total") is not None:
        evidence.append(f"pod_restarts_total: {s.get('pod_restarts_total')}")
    if s.get("crashloop_backoff") is not None:
        evidence.append(f"crashloop_backoff: {s.get('crashloop_backoff')}")
    if s.get("worst_pod") is not None:
        evidence.append(f"worst_pod: {s.get('worst_pod')}")

    # IMPORTANT: actions are strictly from remediation commands/verify
    next_actions = _select_actions_from_remediation(ctx, max_actions=5)

    # Root cause should be conservative: category or unknown
    root_cause = s.get("suspected_category") or "unknown"

    out = {
        "llm_summary": {
            "root_cause": str(root_cause),
            "key_evidence": evidence[:8],
            "next_actions": next_actions,
        },
        "risk_notes": [f"LLM unavailable ({reason}); using deterministic fallback."],
        "confidence": "low",
    }

    # Optional: validate against schema so you never write invalid JSON structure
    try:
        _ = LLMOutput(**out)
    except Exception:
        # ultra-safe fallback (should almost never hit)
        out = {
            "llm_summary": {
                "root_cause": "unknown",
                "key_evidence": [f"fallback_reason: {reason}"],
                "next_actions": next_actions,
            },
            "risk_notes": [f"LLM unavailable ({reason}); schema validation failed in fallback."],
            "confidence": "low",
        }

    return out

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
        return ctx.summary["llm"]

    start = time.time()
    try:
        raw = client.generate_json(model=model, prompt=prompt)

        # raw must be dict; if client returns str, decode here
        if isinstance(raw, str):
            raw = json.loads(raw)

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
        print("[DBG] LLM Enrich succeeded")
        print(ctx.summary["llm"])

        return ctx.summary["llm"]

    except TimeoutError:
        ctx.summary["llm"] = {
            "status": "timeout",
            "provider": "ollama",
            "model": model,
            "latency_ms": int((time.time() - start) * 1000),
            "system_prompt": SYSTEM_PROMPT,
            "input_digest": build_input_digest(ctx),
            "output": fallback_output_from_ctx(ctx, reason="timeout"),
            "error": "LLM call timed out",
        }
        return ctx.summary["llm"]

    except Exception as e:
        ctx.summary["llm"] = {
            "status": "error",
            "provider": "ollama",
            "model": model,
            "latency_ms": int((time.time() - start) * 1000),
            "system_prompt": SYSTEM_PROMPT,
            "input_digest": build_input_digest(ctx),
            "output": fallback_output_from_ctx(ctx, reason=f"exception:{type(e).__name__}"),
            "error": str(e),
        }
        return ctx.summary["llm"]