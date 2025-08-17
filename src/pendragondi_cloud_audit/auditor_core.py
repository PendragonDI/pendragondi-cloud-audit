from typing import List, Dict, Optional
from providers import get_provider

def scan_bucket(provider_name: str, bucket: str, days_stale: int, limit: Optional[int] = None) -> List[Dict]:
    # Lazy import and provider guard
    try:
        provider = get_provider(provider_name)
    except ImportError as e:
        msg = str(e)
        # Normalize messages to user-friendly install hints
        if "boto3" in msg or "AWS support" in msg:
            raise RuntimeError("AWS provider not installed. Install with: pip install pendragondi-cloud-audit[aws]")
        if "google" in msg or "GCS support" in msg:
            raise RuntimeError("GCS provider not installed. Install with: pip install pendragondi-cloud-audit[gcs]")
        if "azure" in msg or "Azure support" in msg:
            raise RuntimeError("Azure provider not installed. Install with: pip install pendragondi-cloud-audit[azure]")
        raise

    # Provider scan with targeted error messaging
    try:
        return provider.scan(bucket=bucket, days_stale=days_stale, limit=limit)
    except PermissionError:
        raise RuntimeError(f"Permission denied accessing {bucket}. Check credentials and bucket permissions.")
    except FileNotFoundError:
        raise RuntimeError(f"Bucket or container '{bucket}' not found or inaccessible.")
    except ConnectionError:
        raise RuntimeError(f"Network connection error while scanning '{bucket}'. Check connectivity and retry.")
    except Exception as e:
        # Fallback: include provider name to aid debugging without leaking secrets
        raise RuntimeError(f"Unexpected error scanning '{bucket}' via {provider_name}: {e}")
