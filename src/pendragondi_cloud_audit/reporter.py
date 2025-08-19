# src/pendragondi_cloud_audit/reporter.py

import html
import csv
import json
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime

# Preferred column ordering for readability; anything else is appended afterward.
PREFERRED_ORDER = ["path", "status", "size", "last_modified", "duplicate_id"]


def _ensure_status(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Backfill a 'status' string for reporting if providers only emit is_stale/duplicate_id.
    Priority: duplicate > stale > active
    """
    for r in records:
        if "status" in r and r["status"]:
            continue
        if r.get("duplicate_id"):
            r["status"] = "duplicate"
        elif r.get("is_stale"):
            r["status"] = "stale"
        else:
            r["status"] = "active"
    return records


def _format_cell(value: Any) -> str:
    """Format values for HTML/CSV: datetimes -> ISO, everything else -> str."""
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def _row_color(status: str) -> str:
    # duplicate -> soft yellow, stale -> soft red/pink
    if "duplicate" in status:
        return "#fff3cd"
    elif "stale" in status:
        return "#f8d7da"
    return ""


def _union_headers(records: List[Dict[str, Any]]) -> List[str]:
    """Create a stable header list: preferred order first, then any extras sorted."""
    all_keys = set()
    for r in records:
        all_keys.update(r.keys())
    # Make sure preferred keys that are present appear first in that order
    ordered = [k for k in PREFERRED_ORDER if k in all_keys]
    # Append any remaining keys in alpha order
    remaining = sorted(k for k in all_keys if k not in ordered)
    return ordered + remaining


def save_html_report(metadata: List[Dict[str, Any]], output_path: str) -> None:
    if not metadata:
        metadata = [{"message": "No objects found or bucket empty"}]

    # Backfill status before counting/formatting
    metadata = _ensure_status(metadata)

    headers = _union_headers(metadata)

    # Summary counts
    total = len(metadata)
    stale = sum(1 for r in metadata if str(r.get("status", "")).lower() == "stale")
    dups = sum(1 for r in metadata if str(r.get("status", "")).lower() == "duplicate")

    # Build rows
    rows_html = []
    for row in metadata:
        status = str(row.get("status", ""))
        color = _row_color(status)
        cells = "".join(
            f"<td>{html.escape(_format_cell(row.get(h, '')))}</td>"
            for h in headers
        )
        rows_html.append(f'<tr style="background-color:{color}">{cells}</tr>')

    # HTML shell
    table = [
        "<html><head><meta charset='utf-8'><title>Cloud Audit Report</title>",
        "<style>",
        "table { border-collapse: collapse; width: 100%; }",
        "th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }",
        "th { background-color: #f2f2f2; }",
        "body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif; }",
        "</style></head><body>",
        "<h2>Cloud Audit Report</h2>",
        f"<p>Total Files: {total} &bull; Stale: {stale} &bull; Duplicates: {dups}</p>",
        "<table>",
        "<tr>" + "".join(f"<th>{html.escape(h)}</th>" for h in headers) + "</tr>",
        *rows_html,
        "</table></body></html>",
    ]

    Path(output_path).write_text("\n".join(table), encoding="utf-8")


def save_csv_report(metadata: List[Dict[str, Any]], output_path: str) -> None:
    if not metadata:
        metadata = [{"message": "No objects found or bucket empty"}]

    # Ensure status and stable headers
    metadata = _ensure_status(metadata)
    headers = _union_headers(metadata)

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        for row in metadata:
            writer.writerow({h: _format_cell(row.get(h, "")) for h in headers})


def save_json_report(metadata: List[Dict[str, Any]], output_path: str) -> None:
    if not metadata:
        metadata = [{"message": "No objects found or bucket empty"}]

    # Ensure status and make datetimes JSON-friendly
    metadata = _ensure_status(metadata)

    def _jsonify(obj: Any) -> Any:
        if isinstance(obj, datetime):
            return obj.isoformat()
        return obj

    norm = [{k: _jsonify(v) for k, v in m.items()} for m in metadata]
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(norm, f, indent=2)


def save_report(metadata: List[Dict[str, Any]], output_path: str) -> None:
    ext = Path(output_path).suffix.lower()
    if ext == ".csv":
        save_csv_report(metadata, output_path)
    elif ext == ".html":
        save_html_report(metadata, output_path)
    elif ext == ".json":
        save_json_report(metadata, output_path)
    else:
        raise ValueError(f"Unsupported file extension: {ext}")


# Backwards-compat exports (optional)
def export_html(metadata, output_path):  # pragma: no cover
    save_html_report(metadata, output_path)


def export_csv(metadata, output_path):  # pragma: no cover
    save_csv_report(metadata, output_path)


def export_json(metadata, output_path):  # pragma: no cover
    save_json_report(metadata, output_path)
