import pytest

from unittest.mock import Mock
from unittest.mock import MagicMock
from unittest.mock import patch
from unittest import TestCase

from exports.google_cloud_storage import GoogleCloudStorage



@patch("exports.google_cloud_storage.storage.Client.from_service_account_json")
def test_GCS_simple_init_keyfile(mock_from_json):
    # catching the Client
    mock_client = MagicMock()
    mock_from_json.return_value = mock_client

    gcs = GoogleCloudStorage("bucket_name", "app_name", "directory_name", "/key/file.json")

    assert gcs.directory == "directory_name"
    assert gcs.app_name == "app_name"
    mock_from_json.assert_called_once_with("/key/file.json")
    mock_client.get_bucket.assert_called_once_with("bucket_name")

@patch("exports.google_cloud_storage.storage.Client")
def test_GCS_simple_init_no_keyfile(mock_client):
    gcs = GoogleCloudStorage("bucket_name", "app_name", "directory_name")

    assert gcs.directory == "directory_name"
    assert gcs.app_name == "app_name"
    mock_client.assert_called_once_with()


@patch("exports.google_cloud_storage.storage.Client")
@patch("exports.google_cloud_storage.uuid")
def test_GCS_create_metadata(mock_uuid, mock_client):

    mock_uuid.uuid1.return_value = 123

    gcs = GoogleCloudStorage("bucket_name", "app_name", "directory_name")

    import_data = {
        "scan_type": "ABC",
        "foo": "bar"
    }

    meta = gcs.create_metadata(import_data)

    assert meta["scan_type"] == import_data["scan_type"]
    assert meta["uuid"] == "123"
    assert meta["import_data"] == import_data


@patch("exports.google_cloud_storage.storage.Client")
def test_GCS_export_scan(MockClient):
    # catching the Client
    mock_client = MagicMock()
    MockClient.return_value = mock_client

    # catching the bucket
    mock_bucket = MagicMock()
    mock_client.get_bucket.return_value = mock_bucket

    # catching the blob
    mock_blob = MagicMock()
    mock_bucket.blob.return_value = mock_blob

    gcs = GoogleCloudStorage("bucket_name", "app_name", "directory_name")

    import_data = {
        "scan_type": "ABC",
        "foo": "bar"
    }

    # hack: use the pytest file itself as a scan
    gcs.export_scan(import_data, __file__)

    mock_blob.open.assert_called_once_with(mode="wb")

