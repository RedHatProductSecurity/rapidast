import os
from unittest.mock import MagicMock
from unittest.mock import patch

import pytest

import configmodel
from scanners.zap.zap_none import ZapNone


@pytest.fixture(scope="function")
def test_config():
    return configmodel.RapidastConfigModel({"application": {"url": "http://example.com"}})


@patch("os.path.exists")
@patch("scanners.zap.zap.shutil.copy")
@patch("scanners.zap.zap.shutil.copytree")
@patch("scanners.zap.zap.tarfile")
def test_zap_none_postprocess_copy_site_tree_path(mock_tarfile, mock_copytree, mock_copy, mock_exists, test_config):
    mock_exists.return_value = True

    test_zap = ZapNone(config=test_config)
    with patch.object(test_zap, "_copy_site_tree") as mock_copy_site_tree:
        test_zap.postprocess()
        mock_copy_site_tree.assert_called_once()


@patch("os.path.exists")
@patch("shutil.copy")
def test_copy_site_tree_success(mock_copy, mock_exists, test_config):
    mock_exists.return_value = True
    test_zap = ZapNone(config=test_config)
    test_zap._copy_site_tree()

    mock_copy.assert_called_once_with(
        os.path.join(test_zap.host_work_dir, "session_data/zap_site_tree.json"), test_zap.results_dir
    )


@patch("os.path.exists")
@patch("shutil.copy")
def test_copy_site_tree_file_not_found(mock_copy, mock_exists, test_config):
    mock_exists.return_value = False
    test_zap = ZapNone(config=test_config)
    test_zap._copy_site_tree()

    assert not mock_copy.called
