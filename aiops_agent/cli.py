import typer
import time
import requests

from datetime import datetime, timezone

from .analyzer.llm_enrich import enrich_with_llm
from .config import load_settings
from .incident import IncidentContext
from .report import print_report, save_json
from .prometheus_client import PrometheusClient
from .collector.prometheus_v2 import collect_namespace_health_v2
from .collector.loki import collect_error_logs
from .collector.k8s_inspect import inspect_k8s_ports
from .analyzer.triage import triage_incident
from .analyzer.triage_v2 import triage_incident_v2
from .gitops.patches import generate_gitops_patches, dump_patches_yaml
from .analyzer.correlate import correlate_prom_loki
from aiops_agent.analyzer.remediation_v1 import remediation_v1

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="AIOps CLI for AKS (Prometheus + Loki + GitOps)",
)

def _argocd_headers(token: str) -> dict:
    return {
        "Authorization": f"Bearer {token}",
        "Cookie": f"argocd.token={token}",
    }


def _request_with_retry(
    method: str,
    url: str,
    headers: dict,
    timeout: int = 30,
    verify: bool = True,
    json_body: dict | None = None,
) -> dict:
    delay_s = 1
    last_exc: Exception | None = None
    for _ in range(3):
        try:
            resp = requests.request(
                method,
                url,
                headers=headers,
                timeout=timeout,
                verify=verify,
                json=json_body,
            )
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException as exc:
            last_exc = exc
            time.sleep(delay_s)
            delay_s = min(delay_s * 2, 5)
    raise last_exc or RuntimeError("Argo CD request failed without exception.")


def _argocd_sync(server: str, token: str, app_name: str, verify: bool) -> dict:
    url = f"{server.rstrip('/')}/api/v1/applications/{app_name}/sync"
    headers = _argocd_headers(token)
    headers["Content-Type"] = "application/json"
    return _request_with_retry("POST", url, headers, verify=verify, json_body={})


def _argocd_get(server: str, token: str, app_name: str, verify: bool) -> dict:
    url = f"{server.rstrip('/')}/api/v1/applications/{app_name}"
    return _request_with_retry("GET", url, _argocd_headers(token), verify=verify)


def _wait_argocd_healthy(
    server: str,
    token: str,
    app_name: str,
    timeout_s: int,
    poll_s: int,
    verify: bool,
) -> dict:
    deadline = time.monotonic() + timeout_s
    last = {}
    while time.monotonic() < deadline:
        last = _argocd_get(server, token, app_name, verify)
        status = last.get("status", {})
        sync_status = (status.get("sync") or {}).get("status")
        health_status = (status.get("health") or {}).get("status")
        if sync_status == "Synced" and health_status == "Healthy":
            return {
                "sync_status": sync_status,
                "health_status": health_status,
                "raw": last,
            }
        time.sleep(poll_s)
    return {
        "sync_status": (last.get("status", {}).get("sync") or {}).get("status"),
        "health_status": (last.get("status", {}).get("health") or {}).get("status"),
        "raw": last,
        "timeout": True,
    }


@app.callback()
def _root() -> None:
    """
    AIOps agent CLI entrypoint.
    """

@app.command(help="Generate an incident context report (read-only).")
def incident(
    out: str = typer.Option("incident_report.json", help="Output JSON file"),
    quiet: bool = typer.Option(False, "--quiet", help="Do not print report to terminal"),
    emit_patch: str | None = typer.Option(None, "--emit-patch", help="Write GitOps remediation patch YAML to this file"),
):
    settings = load_settings()

    ctx = IncidentContext(
        generated_at=datetime.now(timezone.utc),
        lookback_minutes=settings.lookback_minutes,
        namespace=settings.namespace,
        app_label=settings.app_label,
        prom_queries={},
        loki_queries={},
        summary={
            "status": "mvp",
            "note": "Next: query Prometheus/Loki and add correlation.",
        },
    )
    # Prometheus: collect generic namespace signals
    try:
        prom_queries, prom_summary = collect_namespace_health_v2(settings)
        ctx.prom_queries.update(prom_queries)
        ctx.summary.update(prom_summary)
        ctx.summary["prometheus_status"] = "ok"
    except Exception as e:
        # 不让采集失败影响整个报告生成（AIOps 要“降级可用”）
        ctx.summary["prometheus_status"] = "error"
        ctx.summary["prometheus_error"] = str(e)

    # Loki: collect error logs
    try:
        loki_queries, loki_summary = collect_error_logs(settings)
        ctx.loki_queries.update(loki_queries)
        ctx.summary.update(loki_summary)
        ctx.summary["loki_status"] = "ok"
    except Exception as e:
        ctx.summary["loki_status"] = "error"
        ctx.summary["loki_error"] = str(e)
        ctx.summary["error_log_count"] = None
    

    def _dbg(stage: str, ctx):
        keys = sorted(list((ctx.summary or {}).keys()))
        print(f"\n[DBG] after {stage}: summary keys ({len(keys)}): {keys}\n")

    # Correlate Prometheus + Loki signals
    correlate_prom_loki(ctx, settings, top_n=5); 

    # K8s port/probe/endpoints inspection (for port mismatch detection)
    try:
        inspect_k8s_ports(ctx, settings)
        ctx.summary["k8s_inspect_status"] = "ok"
    except Exception as e:
        ctx.summary["k8s_inspect_status"] = "error"
        ctx.summary["k8s_inspect_error"] = str(e)

    # Analyze / triage
    triage_incident_v2(ctx); 
    
    # Remediation suggestions
    remediation_v1(ctx, settings); 

    # LLM enrichment
    enrich_with_llm(ctx, settings)

    # Emit GitOps patch if requested
    if emit_patch:
        patches = generate_gitops_patches(ctx)
        patch_yaml = dump_patches_yaml(patches)
        with open(emit_patch, "w", encoding="utf-8") as f:
            f.write(patch_yaml)
        ctx.summary["gitops_patch_file"] = emit_patch

    # Save report JSON
    save_json(ctx, out)
    if not quiet:
        print_report(ctx)
    typer.echo(f"OK: generated incident report -> {out}")


@app.command(help="Post-merge: sync Argo CD prod app and verify signals.")
def sync_prod(
    out: str = typer.Option("incident_report.json", help="Output JSON file"),
    verify: bool | None = typer.Option(None, "--verify/--no-verify", help="Verify metrics/logs after sync"),
):
    settings = load_settings()
    if not settings.argocd_server or not settings.argocd_token:
        raise typer.BadParameter("ARGOCD_SERVER and ARGOCD_TOKEN must be set for sync.")

    server = settings.argocd_server
    if server.startswith("http://"):
        server = f"https://{server.removeprefix('http://')}"

    verify_after = settings.argocd_verify_after_sync if verify is None else verify
    started_at = datetime.now(timezone.utc)
    sync_result = _argocd_sync(
        server,
        settings.argocd_token,
        settings.argocd_app_prod,
        settings.argocd_insecure is False,
    )
    wait_result = _wait_argocd_healthy(
        server,
        settings.argocd_token,
        settings.argocd_app_prod,
        settings.argocd_sync_timeout_s,
        settings.argocd_poll_interval_s,
        settings.argocd_insecure is False,
    )

    ctx = IncidentContext(
        generated_at=started_at,
        lookback_minutes=settings.lookback_minutes,
        namespace=settings.namespace,
        app_label=settings.app_label,
        prom_queries={},
        loki_queries={},
        summary={
            "status": "post-merge",
            "argocd": {
                "app": settings.argocd_app_prod,
                "server": server,
                "sync_request": sync_result,
                "sync_status": wait_result.get("sync_status"),
                "health_status": wait_result.get("health_status"),
                "sync_timeout": wait_result.get("timeout", False),
            },
        },
    )

    if verify_after:
        try:
            prom_queries, prom_summary = collect_namespace_health_v2(settings)
            ctx.prom_queries.update(prom_queries)
            ctx.summary.update(prom_summary)
            ctx.summary["prometheus_status"] = "ok"
        except Exception as e:
            ctx.summary["prometheus_status"] = "error"
            ctx.summary["prometheus_error"] = str(e)

        try:
            loki_queries, loki_summary = collect_error_logs(settings)
            ctx.loki_queries.update(loki_queries)
            ctx.summary.update(loki_summary)
            ctx.summary["loki_status"] = "ok"
        except Exception as e:
            ctx.summary["loki_status"] = "error"
            ctx.summary["loki_error"] = str(e)
            ctx.summary["error_log_count"] = None

    save_json(ctx, out)
    typer.echo(f"OK: post-merge sync report -> {out}")


@app.command(help="Alias for sync-prod.")
def post_merge(
    out: str = typer.Option("incident_report.json", help="Output JSON file"),
    verify: bool | None = typer.Option(None, "--verify/--no-verify", help="Verify metrics/logs after sync"),
):
    sync_prod(out=out, verify=verify)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
