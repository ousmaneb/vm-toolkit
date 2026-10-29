"""Copies of the database backups kept off the platform: S3-compatible storage or Azure Blob Storage.

[backup] target in config.toml picks the destination:
  "s3://bucket/prefix"        AWS S3, Railway buckets, Cloudflare R2, Backblaze, MinIO. Credentials come from
                              AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY, and AWS_ENDPOINT_URL for non-AWS stores.
  "azure://container/prefix"  Azure Blob Storage, with AZURE_STORAGE_CONNECTION_STRING.
"""

from pathlib import Path
from urllib.parse import urlparse

from .config import ConfigError, Settings, get_secret


class BackupError(Exception):
    pass


def _target(settings: Settings) -> tuple[str, str, str] | None:
    target = str(settings.section("backup").get("target", "")).strip()
    if not target:
        return None
    url = urlparse(target)
    if url.scheme not in ("s3", "azure") or not url.netloc:
        raise ConfigError(f'[backup] target must look like "s3://bucket/prefix" or "azure://container/prefix", '
                          f"not {target!r}")
    return url.scheme, url.netloc, url.path.strip("/")


def _key(prefix: str, name: str) -> str:
    return f"{prefix}/{name}" if prefix else name


def upload(settings: Settings, path: Path, keep: int = 30) -> str | None:
    """Upload one backup file and delete the oldest remote copies beyond `keep`. None if no target is set."""
    target = _target(settings)
    if target is None:
        return None
    scheme, bucket, prefix = target
    stem = settings.db_path.stem
    try:
        if scheme == "s3":
            removed = _s3(bucket, prefix, path, stem, keep)
        else:
            removed = _azure(bucket, prefix, path, stem, keep)
    except ImportError:
        raise ConfigError('Off-site backups need extra packages: pip install -e ".[backup]"') from None
    note = f"; removed {removed} older remote copies" if removed else ""
    return f"Uploaded to {scheme}://{bucket}/{_key(prefix, path.name)}{note}."


def _s3(bucket: str, prefix: str, path: Path, stem: str, keep: int) -> int:
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError

    # boto3 reads AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION and AWS_ENDPOINT_URL itself.
    s3 = boto3.client("s3")
    try:
        s3.upload_file(str(path), bucket, _key(prefix, path.name), ExtraArgs={"ServerSideEncryption": "AES256"})
        listed = s3.list_objects_v2(Bucket=bucket, Prefix=_key(prefix, f"{stem}-")).get("Contents", [])
        old = sorted(o["Key"] for o in listed if o["Key"].endswith(".db"))[:-keep] if keep > 0 else []
        for key in old:
            s3.delete_object(Bucket=bucket, Key=key)
    except (BotoCoreError, ClientError) as e:
        raise BackupError(f"Off-site backup to s3://{bucket} failed: {e}") from None
    return len(old)


def _azure(container: str, prefix: str, path: Path, stem: str, keep: int) -> int:
    from azure.core.exceptions import AzureError
    from azure.storage.blob import BlobServiceClient

    connection = get_secret("AZURE_STORAGE_CONNECTION_STRING", required=True)
    try:
        client = BlobServiceClient.from_connection_string(connection).get_container_client(container)
        with path.open("rb") as f:
            client.upload_blob(_key(prefix, path.name), f, overwrite=True)
        names = sorted(b.name for b in client.list_blobs(name_starts_with=_key(prefix, f"{stem}-"))
                       if b.name.endswith(".db"))
        old = names[:-keep] if keep > 0 else []
        for name in old:
            client.delete_blob(name)
    except AzureError as e:
        raise BackupError(f"Off-site backup to azure://{container} failed: {type(e).__name__}: {e}") from None
    return len(old)
