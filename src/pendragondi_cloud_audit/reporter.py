import html
import csv
from pathlib import Path
from typing import List, Dict

def row_color(status: str) -> str:
    if "duplicate" in status:
        return "#fff3cd"
    elif "stale" in status:
        return "#f8d7da"
    return ""

def save_html_report(metadata: List[Dict], output_path: str):
    if not metadata:
        metadata = [{"message": "No objects found or bucket empty"}]

    headers = metadata[0].keys()
    rows = ""
    for row in metadata:
        status = str(row.get("status", ""))
        color = row_color(status)
        cells = "".join(f"<td>{html.escape(str(row.get(h, '')))}</td>" for h in headers)
        rows += f'<tr style="background-color:{color}">{cells}</tr>'

    total = len(metadata)
    stale = sum(1 for r in metadata if "stale" in str(r.get("status", "")))
    dups = sum(1 for r in metadata if "duplicate" in str(r.get("status", "")))

    table = "<html><head><meta charset='utf-8'><title>Cloud Audit Report</title><style>table { border-collapse: collapse; width: 100%; } th, td { border: 1px solid #ccc; padding: 8px; text-align: left; } th { background-color: #f2f2f2; }</style></head><body>"
    table += f"<h2>Cloud Audit Report</h2><p>Total Files: {total} &bull; Stale: {stale} &bull; Duplicates: {dups}</p><table>"
    table += "<tr>" + "".join(f"<th>{html.escape(h)}</th>" for h in headers) + "</tr>"
    table += rows + "</table></body></html>"

    Path(output_path).write_text(table, encoding="utf-8")

def save_csv_report(metadata: List[Dict], output_path: str):
    if not metadata:
        metadata = [{"message": "No objects found or bucket empty"}]

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=metadata[0].keys())
        writer.writeheader()
        writer.writerows(metadata)

def save_report(metadata: List[Dict], output_path: str):
    ext = Path(output_path).suffix.lower()
    if ext == ".csv":
        save_csv_report(metadata, output_path)
    elif ext == ".html":
        save_html_report(metadata, output_path)
    elif ext == ".json":
        export_json(metadata, output_path)
    else:
        raise ValueError(f"Unsupported file extension: {ext}")

def export_html(metadata, output_path):
    save_html_report(metadata, output_path)

def export_csv(metadata, output_path):
    save_csv_report(metadata, output_path)

def export_json(metadata, output_path):
    import json
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
