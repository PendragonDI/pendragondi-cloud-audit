import typer
from pendragondi_cloud_audit.auditor_core import scan_bucket
from pendragondi_cloud_audit.reporter import export_html, export_json, export_csv
from typing import Optional
from pathlib import Path

app = typer.Typer(help="PendragonDI Cloud Audit CLI")

@app.callback()
def main():
    """
    PendragonDI CLI – scan cloud storage for stale or duplicate files.
    Use one of the available commands.
    """
    pass

@app.command()
def scan(
    provider: str = typer.Argument(..., help="Provider name: aws, gcs, or azure"),
    bucket: str = typer.Argument(..., help="Bucket or container name"),
    days_stale: int = typer.Option(90, "--days-stale", help="How many days before file is considered stale"),
    output: str = typer.Option("report.html", "--output", "-o", help="Output file path"),
    format: str = typer.Option("html", "--format", "-f", help="Output format: html, csv, json"),
    limit: Optional[int] = typer.Option(None, "--limit", help="Max number of objects to scan"),
    public: bool = typer.Option(False, "--public", help="Use known public keys for restricted buckets"),
    verbose: bool = typer.Option(False, "--verbose", help="Print scan progress and key results")
):
    data = scan_bucket(
        provider_name=provider,
        bucket=bucket,
        days_stale=days_stale,
        limit=limit,
        public=public,
        verbose=verbose
    )

    if format == "json":
        export_json(data, output)
    elif format == "csv":
        export_csv(data, output)
    else:
        export_html(data, output)

    typer.echo(f"Report saved to {Path(output).resolve()}")


if __name__ == "__main__":
    app()
