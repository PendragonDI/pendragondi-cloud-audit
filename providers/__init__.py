def get_provider(name: str):
    name = (name or '').lower()
    if name == "aws":
        try:
            from . import aws_s3 as p
        except ImportError:
            raise ImportError("AWS support requires boto3. Install with: pip install pendragondi-cloud-audit[aws]")
        return p
    if name == "gcs":
        try:
            from . import gcs as p
        except ImportError:
            raise ImportError("GCS support requires google-cloud-storage. Install with: pip install pendragondi-cloud-audit[gcs]")
        return p
    if name == "azure":
        try:
            from . import azure_blob as p
        except ImportError:
            raise ImportError("Azure support requires azure-storage-blob. Install with: pip install pendragondi-cloud-audit[azure]")
        return p
    raise ImportError(f"Unknown provider '{name}'. Choose one of: aws, gcs, azure.")
