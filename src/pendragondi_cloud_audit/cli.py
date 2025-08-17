import typer
from pendragondi_cloud_audit.auditor_core import scan_bucket
from pendragondi_cloud_audit.reporter import export_html, export_json, export_csv
from typing import Optional
from pathlib import Path

app = typer.Typer()

@app.command()
def scan(
    provider: str = typer.Argument(...),
    bucket: str = typer.Argument(...),
    days_stale: int = typer.Option(90, "--days-stale"),
    output: str = typer.Option("report.html", "--output", "-o"),
    format: str = typer.Option("html", "--format", "-f"),
    limit: Optional[int] = typer.Option(None, "--limit")
):
    data = scan_bucket(provider_name=provider, bucket=bucket, days_stale=days_stale, limit=limit)

    if format == "json":
        export_json(data, output)
    elif format == "csv":
        export_csv(data, output)
    else:
        export_html(data, output)

    typer.echo(f"Report saved to {Path(output).resolve()}")

if __name__ == "__main__":
    app()
