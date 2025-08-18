from datetime import datetime, timezone, timedelta
from collections import defaultdict
from typing import Optional, List, Dict
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
from botocore import UNSIGNED
import requests
from email.utils import parsedate_to_datetime


def scan(bucket: str, days_stale: int, limit: Optional[int] = None, public: bool = False, verbose: bool = False) -> List[Dict]:
    now = datetime.now(timezone.utc)
    stale_cutoff = now.replace(microsecond=0) - timedelta(days=days_stale)
    files = []
    hash_map = defaultdict(list)

    known_keys = {
        "commoncrawl": [
            "crawl-data/CC-MAIN-2024-10/index.html",
            "crawl-data/CC-MAIN-2024-10/segment.paths.gz",
            "crawl-data/CC-MAIN-2024-10/warc.paths.gz"
        ],
        "nyc-tlc": [
            "trip_data_green_2023-01.csv",
            "trip_data_yellow_2023-01.csv"
        ],
        "landsat-pds": [
            "c1/L8/001/002/LC08_L1TP_001002_20200101_20200101_01_RT/LC08_L1TP_001002_20200101_20200101_01_RT_MTL.txt"
        ]
    }

    if public:
        if bucket not in known_keys:
            raise RuntimeError(f"Public mode is not supported for bucket '{bucket}' yet.")

        for key in known_keys[bucket]:
            url = f"https://data.commoncrawl.org/{key}"
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
                    last_modified = now  # fallback to current

                is_stale = last_modified < stale_cutoff
                path = f"s3://{bucket}/{key}"
                fingerprint = (size, last_modified)
                hash_map[fingerprint].append(path)

                files.append({
                    "path": path,
                    "size": size,
                    "last_modified": last_modified,
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
        s3 = boto3.client("s3")
        paginator = s3.get_paginator("list_objects_v2")
        count = 0

        for page in paginator.paginate(Bucket=bucket):
            for obj in page.get("Contents", []):
                path = f"s3://{bucket}/{obj['Key']}"
                size = obj['Size']
                last_modified = obj['LastModified']
                is_stale = last_modified < stale_cutoff

                fingerprint = (size, last_modified)
                hash_map[fingerprint].append(path)

                files.append({
                    "path": path,
                    "size": size,
                    "last_modified": last_modified,
                    "is_stale": is_stale,
                    "duplicate_id": None
                })

                count += 1
                if limit and count >= limit:
                    break
            if limit and count >= limit:
                break

    for group in hash_map.values():
        if len(group) > 1:
            for i, path in enumerate(group):
                for file in files:
                    if file["path"] == path:
                        file["duplicate_id"] = f"group-{hash(path) % 10000}"

    return files
