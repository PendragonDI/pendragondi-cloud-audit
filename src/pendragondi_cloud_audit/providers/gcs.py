import csv
import gzip
import io
from typing import Optional, List, Dict
from datetime import datetime, timezone, timedelta
from collections import defaultdict
import requests
from email.utils import parsedate_to_datetime

try:
    from google.cloud import storage
except ImportError:
    raise ImportError("GCS support requires google-cloud-storage. Install with: pip install pendragondi-cloud-audit[gcs]")

def scan(bucket: str, days_stale: int, limit: Optional[int] = None, public: bool = False, verbose: bool = False) -> List[Dict]:
    now = datetime.now(timezone.utc)
    stale_cutoff = now - timedelta(days=days_stale)
    files = []
    hash_map = defaultdict(list)

    if public:
        # Use live manifest for Sentinel-2
        manifest_url = "https://storage.googleapis.com/gcp-public-data-sentinel-2/index.csv.gz"
        try:
            response = requests.get(manifest_url, timeout=30)
            response.raise_for_status()
            with gzip.open(io.BytesIO(response.content), mode="rt") as f:
                reader = csv.DictReader(f)
                checked = 0
                for row in reader:
                    if limit and checked >= limit:
                        break

                    base_url = row.get("BASE_URL")
                    if not base_url:
                        continue

                    target_url = base_url.rstrip("/") + "/manifest.safe"
                    try:
                        head = requests.head(target_url, timeout=10)
                        if head.status_code != 200:
                            if verbose:
                                print(f"\u2718 Skipped: {target_url} — {head.status_code} {head.reason}")
                            continue

                        size = int(head.headers.get("Content-Length", 0))
                        last_modified_raw = head.headers.get("Last-Modified")
                        last_modified = parsedate_to_datetime(last_modified_raw) if last_modified_raw else now
                        is_stale = last_modified < stale_cutoff

                        gs_path = target_url.replace("https://storage.googleapis.com/", "gs://")
                        fingerprint = (size, last_modified)
                        hash_map[fingerprint].append(gs_path)

                        files.append({
                            "path": gs_path,
                            "size": size,
                            "last_modified": last_modified.isoformat(),
                            "is_stale": is_stale,
                            "duplicate_id": None
                        })

                        if verbose:
                            print(f"\u2714 Found: {gs_path} ({size} bytes)")
                        checked += 1
                    except Exception as e:
                        if verbose:
                            print(f"\u2718 Error: {target_url} — {type(e).__name__}: {e}")
                        continue
        except Exception as e:
            raise RuntimeError(f"Failed to fetch public Sentinel-2 manifest: {e}")

    else:
        client = storage.Client()
        for blob in client.list_blobs(bucket):
            path = f"gs://{bucket}/{blob.name}"
            size = blob.size
            last_modified = blob.updated
            is_stale = last_modified < stale_cutoff

            fingerprint = (size, last_modified)
            hash_map[fingerprint].append(path)

            files.append({
                "path": path,
                "size": size,
                "last_modified": last_modified.isoformat(),
                "is_stale": is_stale,
                "duplicate_id": None
            })

            if limit and len(files) >= limit:
                break

    for group in hash_map.values():
        if len(group) > 1:
            for path in group:
                for file in files:
                    if file["path"] == path:
                        file["duplicate_id"] = f"group-{hash(path) % 10000}"

    return files
