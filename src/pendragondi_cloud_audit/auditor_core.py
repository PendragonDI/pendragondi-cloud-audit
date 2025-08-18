from typing import List, Dict, Optional
from pendragondi_cloud_audit.providers import get_provider
import botocore.exceptions

def scan_bucket(
    provider_name: str,
    bucket: str,
    days_stale: int,
    limit: Optional[int] = None,
    public: bool = False,
    verbose: bool = False
) -> List[Dict]:
    try:
        provider = get_provider(provider_name)
    except ImportError as e:
        msg = str(e)
        if "boto3" in msg or "AWS support" in msg:
            raise RuntimeError("AWS provider not installed. Install with: pip install pendragondi-cloud-audit[aws]")
        if "google" in msg or "GCS support" in msg:
            raise RuntimeError("GCS provider not installed. Install with: pip install pendragondi-cloud-audit[gcs]")
        if "azure" in msg or "Azure support" in msg:
            raise RuntimeError("Azure provider not installed. Install with: pip install pendragondi-cloud-audit[azure]")
        raise

    try:
        return provider.scan(
            bucket=bucket,
            days_stale=days_stale,
            limit=limit,
            public=public,
            verbose=verbose
        )
    except PermissionError:
        raise RuntimeError(f"Permission denied accessing {bucket}. Check credentials and bucket permissions.")
    except FileNotFoundError:
        raise RuntimeError(f"Bucket or container '{bucket}' not found or inaccessible.")
    except ConnectionError:
        raise RuntimeError(f"Network connection error while scanning '{bucket}'. Check connectivity and retry.")
    except botocore.exceptions.ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code == "AccessDenied" and public:
            raise RuntimeError(
                f"Bucket '{bucket}' is public but does not allow listing. "
                f"Using --public mode: scanning known keys only."
            )
        elif code == "AccessDenied":
            raise RuntimeError(
                f"Access denied scanning '{bucket}'. This bucket may be public but does not allow object listing. "
                f"Use --public mode to scan known keys."
            )
        raise
    except Exception as e:
        raise RuntimeError(f"Unexpected error scanning '{bucket}' via {provider_name}: {e}")
