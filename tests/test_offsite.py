import os

import pytest

from vmtoolkit import db
from vmtoolkit.backup import backup
from vmtoolkit.config import ConfigError
from vmtoolkit.offsite import upload


def make_backups(settings, days):
    from datetime import datetime

    db.connect(settings.db_path).close()
    return [backup(settings, now=datetime(2099, 3, day))[0] for day in days]


def test_no_target_means_no_upload(settings):
    assert upload(settings, make_backups(settings, [1])[0]) is None


@pytest.mark.parametrize("target", ["ftp://host/x", "s3://", "bucket-only"])
def test_bad_targets_are_refused(settings, target):
    settings.raw["backup"] = {"target": target}
    with pytest.raises(ConfigError, match="must look like"):
        upload(settings, make_backups(settings, [1])[0])


def test_s3_upload_encrypts_and_prunes(settings, monkeypatch):
    moto = pytest.importorskip("moto")
    import boto3

    for name, value in {"AWS_ACCESS_KEY_ID": "test", "AWS_SECRET_ACCESS_KEY": "test",
                        "AWS_DEFAULT_REGION": "us-east-1"}.items():
        monkeypatch.setenv(name, value)
    monkeypatch.delenv("AWS_ENDPOINT_URL", raising=False)
    with moto.mock_aws():
        s3 = boto3.client("s3")
        s3.create_bucket(Bucket="vmt-backups")
        settings.raw["backup"] = {"target": "s3://vmt-backups/prod"}
        copies = make_backups(settings, [1, 2, 3])
        for copy in copies:
            message = upload(settings, copy, keep=2)
        assert message == "Uploaded to s3://vmt-backups/prod/vmt-2099-03-03.db; removed 1 older remote copies."
        keys = sorted(o["Key"] for o in s3.list_objects_v2(Bucket="vmt-backups")["Contents"])
        assert keys == ["prod/vmt-2099-03-02.db", "prod/vmt-2099-03-03.db"]
        head = s3.head_object(Bucket="vmt-backups", Key="prod/vmt-2099-03-03.db")
        assert head["ServerSideEncryption"] == "AES256"


@pytest.mark.skipif(not os.environ.get("VMT_TEST_AZURITE"), reason="set VMT_TEST_AZURITE to an Azurite connection string")
def test_azure_upload_and_prune(settings, monkeypatch):
    from azure.storage.blob import BlobServiceClient

    connection = os.environ["VMT_TEST_AZURITE"]
    monkeypatch.setenv("AZURE_STORAGE_CONNECTION_STRING", connection)
    container = BlobServiceClient.from_connection_string(connection).get_container_client("vmt-test")
    if not container.exists():
        container.create_container()
    for blob in container.list_blobs():
        container.delete_blob(blob.name)
    settings.raw["backup"] = {"target": "azure://vmt-test/prod"}
    for copy in make_backups(settings, [1, 2, 3]):
        message = upload(settings, copy, keep=2)
    assert message.endswith("removed 1 older remote copies.")
    assert sorted(b.name for b in container.list_blobs()) == ["prod/vmt-2099-03-02.db", "prod/vmt-2099-03-03.db"]
