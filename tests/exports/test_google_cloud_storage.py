import datetime
from unittest.mock import MagicMock
from unittest.mock import Mock
from unittest.mock import mock_open
from unittest.mock import patch

import pytest

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
        "engagement_name": "engagement",
        "product_name": "product",
    }

    meta = gcs.create_metadata(import_data)

    assert meta["scan_type"] == import_data["scan_type"]
    assert meta["uuid"] == "123"
    assert meta["import_data"] == import_data
    assert meta["import_data"]["engagement_name"] == "engagement"
    assert meta["import_data"]["product_name"] == "product"


@patch("exports.google_cloud_storage.storage.Client")
@patch("exports.google_cloud_storage.datetime.datetime")
@patch("exports.google_cloud_storage.random.choices")
def test_GCS_export_scan(MockRandom, MockDateTime, MockClient):
    # Forcing the random
    MockRandom.return_value = "abcdef"

    # Forcing the date
    mock_now = MagicMock()
    mock_now.isoformat.return_value = "2024-01-31T00:00:00"
    MockDateTime.now.return_value = mock_now

    # catching the Client
    mock_client = MagicMock()
    MockClient.return_value = mock_client

    # catching the bucket
    mock_bucket = MagicMock()
    mock_client.get_bucket.return_value = mock_bucket

    # catching the blob
    mock_blob = MagicMock()
    mock_bucket.blob.return_value = mock_blob

    # catching the data written to the blob
    mock_open_method = mock_open()
    mock_blob.open = mock_open_method

    gcs = GoogleCloudStorage("bucket_name", "app_name", "directory_name")

    import_data = {"scan_type": "ABC", "foo": "bar"}

    # hack: use the pytest file itself as a scan
    gcs.export_scan(import_data, __file__)

    mock_bucket.blob.assert_called_once_with("directory_name/2024-01-31T00:00:00-RapiDAST-app_name-abcdef.tgz")

    mock_open_method.assert_called_once_with(mode="wb")
