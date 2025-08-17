import typer
from typing import Optional
from pendragondi_cloud_audit.auditor_core import scan_bucket
from pendragondi_cloud_audit.reporter import save_report


app = typer.Typer(help="PendragonDI Cloud Audit - read-only, metadata-only scans for stale/duplicate objects.")

@app.command()
def scan(
    provider: str = typer.Argument(..., help="aws | gcs | azure"),
    bucket: str = typer.Argument(..., help="Bucket/Container name or URL (Azure supports container URL)."),
    days_stale: int = typer.Option(90, "--days-stale", "-d", help="Days since last modified to label as stale."),
    output: str = typer.Option("report.html", "--output", "-o", help="Output file (.html or .csv)."),
    limit: Optional[int] = typer.Option(None, "--limit", help="Optional max number of objects to scan (sampling/testing).")
):
    allowed = {"aws", "gcs", "azure"}
    if provider not in allowed:
        raise typer.BadParameter(f"provider must be one of: {', '.join(sorted(allowed))}")
    metadata = scan_bucket(provider, bucket, days_stale, limit=limit)
    save_report(metadata, output)
    typer.echo(f"Report saved to {output}")

if __name__ == "__main__":
    app()
