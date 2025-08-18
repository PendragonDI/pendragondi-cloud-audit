from typing import Optional, List, Dict
from datetime import datetime, timezone, timedelta
from collections import defaultdict
import hashlib
import requests
from email.utils import parsedate_to_datetime

try:
    from google.cloud import storage
except ImportError:
    raise ImportError("GCS support requires google-cloud-storage. Install with: pip install pendragondi-cloud-audit[gcs]")


def scan(bucket: str, days_stale: int, limit: Optional[int] = None, public: bool = False, verbose: bool = False) -> List[Dict]:
    now = datetime.now(timezone.utc)
    stale_cutoff = now.replace(microsecond=0) - timedelta(days=days_stale)
    files = []
    hash_map = defaultdict(list)

    known_keys = {
        "gcp-public-data-landsat": [
            "LC08/01/001/002/LC08010002013197LGN00/LC08010002013197LGN00_MTL.txt"
        ],
        "gcp-public-data-sentinel-2": [
            "tiles/30/U/UH/2023/8/10/0/B02.jp2"
        ],
        "gcp-public-data-noaa-goes-16": [
            "ABI-L1b-RadC/2023/001/00/OR_ABI-L1b-RadC-M6C01_G16_s20230010000394_e20230010011102_c20230010011156.nc"
        ]
    }

    if public:
        if bucket not in known_keys:
            raise RuntimeError(f"Public mode is not supported for bucket '{bucket}' yet.")

        for key in known_keys[bucket]:
            url = f"https://storage.googleapis.com/{bucket}/{key}"
            try:
                resp = requests.head(url, timeout=10)
                if resp.status_code != 200:
                    if verbose:
                        print(f"✘ Skipped: {url} — {resp.status_code} {resp.reason}")
                    continue

                size = int(resp.headers.get("Content-Length", 0))
                last_modified_raw = resp.headers.get("Last-Modified")
                if last_modified_raw:
                    last_modified = parsedate_to_datetime(last_modified_raw)
                else:
                    last_modified = now  # fallback to now if not present

                is_stale = last_modified < stale_cutoff
                path = f"gs://{bucket}/{key}"
                fingerprint = (size, last_modified)
                hash_map[fingerprint].append(path)

                files.append({
                    "path": path,
                    "size": size,
                    "last_modified": last_modified.isoformat(),
                    "is_stale": is_stale,
                    "duplicate_id": None
                })

                if verbose:
                    print(f"✔ Found object: {path} ({size} bytes)")

            except Exception as e:
                if verbose:
                    print(f"✘ Skipped: {url} — {type(e).__name__}: {e}")
                continue

    else:
        client = storage.Client()
        stale_cutoff = datetime.now(timezone.utc) - timedelta(days=days_stale)

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
