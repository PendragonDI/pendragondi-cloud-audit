from typing import Optional
try:
    import boto3
    from botocore.config import Config
    from botocore import UNSIGNED
except ImportError:
    raise ImportError("AWS support requires boto3 and botocore. Install with: pip install pendragondi-cloud-audit[aws]")

from datetime import datetime, timezone, timedelta
import hashlib
from collections import defaultdict
from .utils import finalize_status

def _file_hash(obj):
    # Conservative duplicate key: path + size + mtime to avoid false positives
    return hashlib.sha1(
        f"{obj['Key']}|{obj['Size']}|{obj['LastModified']}".encode()
    ).hexdigest()

def scan(bucket: str, days_stale: int, limit: Optional[int] = None):
    # List of known public buckets that don't need credentials
    PUBLIC_BUCKETS = [
        'commoncrawl', 'nyc-tlc', 'landsat-pds', 'sentinel-s2-l1c',
        'opendata', 'registry.opendata.aws', 'aws-publicdatasets'
    ]
    
    # Use unsigned requests for public buckets
    if bucket in PUBLIC_BUCKETS or bucket.startswith('aws-'):
        config = Config(
            signature_version=UNSIGNED,
            retries={"max_attempts": 10, "mode": "adaptive"}
        )
    else:
        config = Config(retries={"max_attempts": 10, "mode": "adaptive"})
    
    s3 = boto3.client("s3", config=config, region_name='us-east-1')
    paginator = s3.get_paginator('list_objects_v2')
    stale_cutoff = datetime.now(timezone.utc) - timedelta(days=days_stale)
    files = []
    hash_map = defaultdict(list)

    for page in paginator.paginate(Bucket=bucket):
        for obj in page.get("Contents", []):
            path = f"s3://{bucket}/{obj['Key']}"
            size = obj['Size']
            last_modified = obj['LastModified']
            last_modified_str = last_modified.strftime("%Y-%m-%d %H:%M:%S")
            status = []
            if last_modified < stale_cutoff:
                status.append("stale")
            hash_val = _file_hash(obj)
            hash_map[hash_val].append(path)
            files.append({
                "path": path,
                "size": size,
                "last_modified": last_modified_str,
                "status": status,
            })
            if limit and len(files) >= limit:
                break
        if limit and len(files) >= limit:
            break

    finalize_status(files, hash_map)
    return files
