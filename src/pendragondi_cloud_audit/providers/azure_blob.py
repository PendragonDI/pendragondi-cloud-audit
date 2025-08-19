# src/pendragondi_cloud_audit/providers/azure_blob.py
from typing import Optional, List, Dict
from datetime import datetime, timezone, timedelta
from collections import defaultdict
from urllib.parse import urlparse
import os

try:
    from azure.storage.blob import ContainerClient
    from azure.core.exceptions import ResourceNotFoundError, ClientAuthenticationError, HttpResponseError
except ImportError:
    raise ImportError(
        "Azure support requires azure-storage-blob. "
        "Install with: pip install pendragondi-cloud-audit[azure]"
    )


def _container_name_from_url(container_url: str) -> str:
    """
    Extract the container name from an Azure container URL like:
      https://<account>.blob.core.windows.net/<container>[?SAS]
    """
    parsed = urlparse(container_url)
    # path: "/<container>" or "/<container>/"
    path = parsed.path.strip("/")
    # Only first segment is container
    return path.split("/")[0] if path else ""


def scan(
    container: str,
    days_stale: int,
    limit: Optional[int] = None,
    public: bool = False,   # kept for parity with other providers
    verbose: bool = False
) -> List[Dict]:
    """
    List Azure Blob objects (metadata-only), compute staleness and potential duplicates.
    Supports a container name (using AZURE_STORAGE_CONNECTION_STRING) or a full container URL (optionally with SAS).
    """
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=days_stale)
    files: List[Dict] = []
    groups = defaultdict(list)

    # Choose client strategy
    cs = os.getenv("AZURE_STORAGE_CONNECTION_STRING")

    try:
        if container.startswith("https://"):
            client = ContainerClient.from_container_url(container)
            container_name = _container_name_from_url(container) or container
        elif cs:
            client = ContainerClient.from_connection_string(cs, container_name=container)
            container_name = container
        else:
            raise ValueError("Provide a container URL or set AZURE_STORAGE_CONNECTION_STRING")

        count = 0
        for blob in client.list_blobs():
            size = getattr(blob, "size", 0)
            lm = getattr(blob, "last_modified", now)
            if lm and lm.tzinfo is None:
                lm = lm.replace(tzinfo=timezone.utc)

            is_stale = (lm or now) < cutoff

            # Consistent display path across providers
            path = f"az://{container_name}/{blob.name}"

            # Duplicate fingerprint matches other providers: (size, last_modified)
            fp = (size, lm)
            groups[fp].append(path)

            files.append({
                "path": path,
                "size": size,
                "last_modified": lm,
                "is_stale": is_stale,
                "duplicate_id": None,
            })

            count += 1
            if limit and count >= limit:
                break

    except ClientAuthenticationError:
        raise PermissionError("Azure authentication failed; check credentials or SAS/URL permissions.")
    except ResourceNotFoundError:
        raise FileNotFoundError(f"Container '{container}' not found or inaccessible.")
    except HttpResponseError as e:
        status = getattr(e, "status_code", None)
        if status in (401, 403):
            raise PermissionError(f"Access denied for '{container}'.")
        if status == 404:
            raise FileNotFoundError(f"Container '{container}' not found.")
        raise
    except (TimeoutError, ConnectionError):
        raise ConnectionError("Network connection error while listing Azure blobs.")
    except Exception:
        raise

    # Mark duplicates (same style as AWS/GCS)
    for paths in groups.values():
        if len(paths) > 1:
            dup_id = f"group-{abs(hash(tuple(sorted(paths)))) % 10000}"
            for p in paths:
                for f in files:
                    if f["path"] == p:
                        f["duplicate_id"] = dup_id

    if verbose:
        stale_ct = sum(f["is_stale"] for f in files)
        dup_ct = sum(1 for f in files if f["duplicate_id"])
        print(f"Scanned {len(files)} objects • stale={stale_ct} • duplicates={dup_ct}")

    return files
