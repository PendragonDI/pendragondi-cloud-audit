from typing import Optional
try:
    from google.cloud import storage
except ImportError:
    raise ImportError("GCS support requires google-cloud-storage. Install with: pip install pendragondi-cloud-audit[gcs]")

from datetime import datetime, timezone, timedelta
import hashlib
from collections import defaultdict
from .utils import finalize_status

def _file_hash(blob):
    # Conservative duplicate key: path + size + mtime to avoid false positives
    return hashlib.sha1(
        f"{blob.name}|{blob.size}|{blob.updated}".encode()
    ).hexdigest()

def scan(bucket: str, days_stale: int, limit: Optional[int] = None):
    client = storage.Client()
    stale_cutoff = datetime.now(timezone.utc) - timedelta(days=days_stale)
    files = []
    hash_map = defaultdict(list)

    for blob in client.list_blobs(bucket):
        path = f"gs://{bucket}/{blob.name}"
        size = blob.size
        last_modified = blob.updated
        last_modified_str = last_modified.strftime("%Y-%m-%d %H:%M:%S")
        status = []
        if last_modified < stale_cutoff:
            status.append("stale")
        hash_val = _file_hash(blob)
        hash_map[hash_val].append(path)
        files.append({
            "path": path,
            "size": size,
            "last_modified": last_modified_str,
            "status": status,
        })
        if limit and len(files) >= limit:
            break

    finalize_status(files, hash_map)
    return files
