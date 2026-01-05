from rich.console import Console
from rich.table import Table
from datetime import datetime
import json
from typing import Any

from .incident import IncidentContext

console = Console()


def print_report(ctx: IncidentContext) -> None:
    """
    Pretty-print incident report to terminal.
    """
    console.print(
        f"\n[bold]AIOps Incident Report[/bold]  generated_at={ctx.generated_at.isoformat()}"
    )
    console.print(
        f"scope: namespace={ctx.namespace}, app={ctx.app_label}, lookback={ctx.lookback_minutes}m\n"
    )

    # Summary section
    console.print("[bold]Summary[/bold]")
    for k, v in ctx.summary.items():
        console.print(f"- {k}: {v}")

    # Loki logs preview (if exists)
    error_logs = ctx.loki_queries.get("error_logs", {})
    rows = error_logs.get("rows", [])

    if rows:
        table = Table(title="Recent ERROR logs (sample)", show_lines=True)
        table.add_column("timestamp")
        table.add_column("log")

        for r in rows[:10]:
            table.add_row(str(r.get("ts", "")), r.get("line", ""))

        console.print(table)
    else:
        console.print("\n[yellow]No error logs found in this time window.[/yellow]")


def save_json(ctx: IncidentContext, path: str) -> None:
    """
    Save incident report as JSON for audit / replay.
    """
    with open(path, "w", encoding="utf-8") as f:
        json.dump(
            ctx.model_dump(mode="json"),
            f,
            ensure_ascii=False,
            indent=2,
            default=str,
        )