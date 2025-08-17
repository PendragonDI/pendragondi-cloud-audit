import csv
from typing import List, Dict
from datetime import datetime
import html

def save_report(metadata: List[Dict], output_path: str):
    if output_path.endswith(".html"):
        save_html_report(metadata, output_path)
    else:
        save_csv_report(metadata, output_path)

def save_csv_report(metadata: List[Dict], output_path: str):
    if not metadata:
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            f.write("path,size,last_modified,status\n")
        return
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(metadata[0].keys()))
        writer.writeheader()
        writer.writerows(metadata)

def save_html_report(metadata: List[Dict], output_path: str):
    if not metadata:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("<html><body><p>No objects found.</p></body></html>")
        return

    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    headers = list(metadata[0].keys())
    status_colors = {
        "stale": "#fff3cd",
        "duplicate": "#f8d7da",
        "active": "#d4edda"
    }
    def row_color(status: str) -> str:
        for key, color in status_colors.items():
            if key in status:
                return color
        return "#ffffff"

    total = len(metadata)
    stale = sum("stale" in str(r.get("status","")) for r in metadata)
    dups  = sum("duplicate" in str(r.get("status","")) for r in metadata)

    rows = "".join(
        "<tr style='background:%s'>%s</tr>" % (
            row_color(str(row.get("status",""))),
            "".join("<td>%s</td>" % html.escape(str(row.get(h, ""))) for h in headers)
        ) for row in metadata
    )

    html_output = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>PendragonDI Cloud Audit Report</title>
  <style>
    body {{ font-family: sans-serif; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border: 1px solid #bbb; padding: 8px; text-align: left; }}
    th {{ background: #222; color: #fff; }}
    caption {{ caption-side: top; font-weight: bold; font-size: 1.2em; margin-bottom: 12px; }}
  </style>
</head>
<body>
  <p>Total Files: {total} • Stale: {stale} • Duplicates: {dups}</p>
  <table>
    <caption>PendragonDI Cloud Audit Report<br>{now}</caption>
    <thead><tr>{''.join(f'<th>{h}</th>' for h in headers)}</tr></thead>
    <tbody>{rows}</tbody>
  </table>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_output)
