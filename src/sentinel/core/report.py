"""终端渲染（rich）。"""

from __future__ import annotations

from rich.console import Console
from rich.table import Table

from .models import Confidence, TriageReport

console = Console()

_COLORS = {
    Confidence.CONFIRMED: "green",
    Confidence.LIKELY: "green",
    Confidence.UNVERIFIED: "yellow",
    Confidence.UNAVAILABLE: "red",
}


def render(report: TriageReport) -> None:
    console.print(
        f"\n[bold]研判报告[/bold] · {report.kind} · [cyan]{report.target}[/cyan]  ({report.created_at})\n"
    )

    table = Table(show_lines=False, pad_edge=False)
    table.add_column("字段", style="dim", no_wrap=True)
    table.add_column("值", overflow="fold")
    table.add_column("置信度", no_wrap=True)
    table.add_column("来源", no_wrap=True)
    for f in report.findings:
        color = _COLORS.get(f.confidence, "yellow")
        table.add_row(f.key, f.value, f"[{color}]{f.confidence.value}[/{color}]", f.source)
    console.print(table)

    if report.sources:
        st = Table(title="数据源状态", pad_edge=False)
        st.add_column("数据源", no_wrap=True)
        st.add_column("状态", no_wrap=True)
        st.add_column("说明", overflow="fold")
        for s in report.sources:
            st.add_row(s.source, "[green]OK[/green]" if s.ok else "[red]FAIL[/red]", s.detail or s.error)
        console.print(st)

    for n in report.notes:
        console.print(f"[yellow]• {n}[/yellow]")
    console.print()
