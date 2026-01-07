import typer

from datetime import datetime, timezone
from .config import load_settings
from .incident import IncidentContext
from .report import print_report, save_json
from .prometheus_client import PrometheusClient
from .collector.prometheus_v2 import collect_namespace_health_v2
from .collector.loki import collect_error_logs
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
    # Analyze / triage
    triage_incident_v2(ctx); 
    
    # Remediation suggestions
    remediation_v1(ctx, settings); 
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

def main() -> None:
    app()


if __name__ == "__main__":
    main()
