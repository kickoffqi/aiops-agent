import typer

from datetime import datetime, timezone

from .config import load_settings
from .incident import IncidentContext
from .report import print_report, save_json
from .prometheus_client import PrometheusClient
from .collector.prometheus import collect_namespace_health
from .collector.loki import collect_error_logs

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
    # 2) Prometheus: collect generic namespace signals
    try:
        prom_queries, prom_summary = collect_namespace_health(settings)
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


    save_json(ctx, out)
    if not quiet:
        print_report(ctx)
    typer.echo(f"OK: generated incident report -> {out}")

def main() -> None:
    app()


if __name__ == "__main__":
    main()
