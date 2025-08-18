from datetime import datetime, timezone
from collections import defaultdict
from typing import Optional, List, Dict
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
from datetime import datetime, timezone, timedelta


def scan(bucket: str, days_stale: int, limit: Optional[int] = None, public: bool = False) -> List[Dict]:
    s3 = boto3.client("s3", config=Config(signature_version="unsigned") if public else None)
    now = datetime.now(timezone.utc)
    stale_cutoff = now.replace(microsecond=0) - timedelta(days=days_stale)
    files = []
    hash_map = defaultdict(list)

    if public:
        known_keys = {
            "commoncrawl": [
                "crawl-data/CC-MAIN-2023-14/robotstxt.arc.gz",
                "crawl-data/CC-MAIN-2023-14/segments/1680535039241.3/warc/CC-MAIN-20230403061739-20230403091739-00000.warc.gz"
            ],
            "nyc-tlc": [
                "trip\_data\_green\_2023-01.csv",
                "trip\_data\_yellow\_2023-01.csv"
            ],
            "landsat-pds": [
                "c1/L8/001/002/LC08_L1TP_001002_20200101_20200101_01_RT/LC08_L1TP_001002_20200101_20200101_01_RT_MTL.txt"
            ]
        }

        if bucket not in known_keys:
            raise RuntimeError(f"Public mode not supported for bucket '{bucket}'")

        for key in known_keys[bucket]:
            try:
                obj = s3.head_object(Bucket=bucket, Key=key)
                files.append({
                    "path": f"s3://{bucket}/{key}",
                    "size": obj["ContentLength"],
                    "last_modified": obj["LastModified"],
                    "is_stale": obj["LastModified"] < stale_cutoff,
                    "duplicate_id": None
                })
            except ClientError as e:
                continue  # skip inaccessible keys

    else:
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

    # Mark duplicates
    for group in hash_map.values():
        if len(group) > 1:
            for i, path in enumerate(group):
                for file in files:
                    if file["path"] == path:
                        file["duplicate_id"] = f"group-{hash(path) % 10000}"

    return files
