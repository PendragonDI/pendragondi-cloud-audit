from datetime import datetime, timezone, timedelta
from collections import defaultdict
from typing import Optional, List, Dict
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
from botocore import UNSIGNED
import requests
from email.utils import parsedate_to_datetime


def scan(bucket: str, days_stale: int, oversized_mb: int = 0, limit: Optional[int] = None, verbose: bool = False) -> List[Dict]:
    now = datetime.now(timezone.utc)
    stale_cutoff = now.replace(microsecond=0) - timedelta(days=days_stale)
    files = []
    hash_map = defaultdict(list)

    s3 = boto3.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    count = 0

    for page in paginator.paginate(Bucket=bucket):
            for obj in page.get("Contents", []):
                path = f"s3://{bucket}/{obj['Key']}"
                size = obj['Size']
                last_modified = obj['LastModified']
                is_stale = last_modified < stale_cutoff
                is_oversized = (oversized_mb > 0) and (size > oversized_mb * 1024 * 1024)

                fingerprint = (size, last_modified)
                hash_map[fingerprint].append(path)

                files.append({
                    "path": path,
                    "size": size,
                    "last_modified": last_modified,
                    "is_stale": is_stale,
                    "is_oversized": is_oversized,
                    "duplicate_id": None
                })

                count += 1
                if limit and count >= limit:
                    break
            if limit and count >= limit:
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
