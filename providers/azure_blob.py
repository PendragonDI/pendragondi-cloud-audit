from typing import Optional
try:
    from azure.storage.blob import ContainerClient
except ImportError:
    raise ImportError("Azure support requires azure-storage-blob. Install with: pip install pendragondi-cloud-audit[azure]")

from datetime import datetime, timezone, timedelta
import hashlib
from collections import defaultdict
import os
from .utils import finalize_status

def _file_hash(blob):
    # Conservative duplicate key: path + size + mtime to avoid false positives
    return hashlib.sha1(
        f"{blob.name}|{blob.size}|{blob.last_modified}".encode()
    ).hexdigest()

def scan(container: str, days_stale: int, limit: Optional[int] = None):
    cs = os.getenv("AZURE_STORAGE_CONNECTION_STRING")
    if container.startswith("https://"):
        client = ContainerClient.from_container_url(container)
    elif cs:
        client = ContainerClient.from_connection_string(cs, container_name=container)
    else:
        raise ValueError("Provide a container URL or set AZURE_STORAGE_CONNECTION_STRING")

    stale_cutoff = datetime.now(timezone.utc) - timedelta(days=days_stale)
    files = []
    hash_map = defaultdict(list)

    for blob in client.list_blobs():
        path = f"az://{container}/{blob.name}"
        size = blob.size
        last_modified = blob.last_modified
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
