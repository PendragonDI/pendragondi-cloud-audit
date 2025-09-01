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

def scan(bucket: str, days_stale: int, oversized_mb: int = 0, limit: Optional[int] = None, verbose: bool = False) -> List[Dict]:
    now = datetime.now(timezone.utc)
    stale_cutoff = now - timedelta(days=days_stale)
    files = []
    hash_map = defaultdict(list)

    client = storage.Client()
    for blob in client.list_blobs(bucket):
            path = f"gs://{bucket}/{blob.name}"
            size = blob.size
            last_modified = blob.updated
            is_stale = last_modified < stale_cutoff
            is_oversized = (oversized_mb > 0) and (size > oversized_mb * 1024 * 1024)

            fingerprint = (size, last_modified)
            hash_map[fingerprint].append(path)

            files.append({
                "path": path,
                "size": size,
                "last_modified": last_modified.isoformat(),
                "is_stale": is_stale,
                "is_oversized": is_oversized,
                "duplicate_id": None
            })

            if limit and len(files) >= limit:
                break

    # More efficient and correct duplicate marking
    file_map = {file["path"]: file for file in files}
    for fingerprint, group in hash_map.items():
        if len(group) > 1:
            # All files in this group are duplicates. Generate one ID for them.
            dupe_id = f"dupe-group-{hash(fingerprint)}"
            for path in group:
                file_map[path]["duplicate_id"] = dupe_id

    return files
