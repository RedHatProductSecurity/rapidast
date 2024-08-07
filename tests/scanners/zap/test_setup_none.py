# test specifically designed for ZAP in None mode (testing zap_none.py)
from collections import namedtuple
from unittest.mock import mock_open
from unittest.mock import patch

import pytest

import configmodel
from scanners.zap.zap_none import ZapNone


@pytest.fixture(scope="function")
def test_config():
    return configmodel.RapidastConfigModel(
        {"application": {"url": "http://example.com"}}
    )


@patch("scanners.zap.zap_none.platform.system")
@patch("scanners.zap.zap_none.disk_usage")
@patch("scanners.zap.zap_none.logging.warning")
def test_none_handling_ajax(mock_warning, mock_disk_usage, mock_system, test_config):
    test_config.set("scanners.zap.spiderAjax.url", "https://abcdef.jklm")
    test_zap = ZapNone(config=test_config)
    # create a fake automation framework: just an empty `jobs` is sufficient
    test_zap.automation_config = {"jobs": []}

    mock_system.return_value = "Linux"

    # Fake a 64MB /dev/shm (default on containers) to provoke an error
    DiskUsage = namedtuple("DiskUsage", ["total"])
    mock_disk_usage.return_value = DiskUsage(total=64 * 1024 * 1024)

    # Fake a CGroup V2 environment
    with patch("builtins.open", mock_open(read_data="42")) as mock_pidsmax:
        test_zap._setup_ajax_spider()

    mock_pidsmax.assert_called_once_with("/sys/fs/cgroup/pids.max", encoding="utf-8")
    mock_warning.assert_any_call(
        "Number of threads may be too low for SpiderAjax: cgroupv2 pids.max=42"
    )
    mock_warning.assert_any_call(
        "Insufficient shared memory to run an Ajax Spider correctly (67108864 bytes). "
        "Make sure that /dev/shm/ is at least 1GB in size [ideally at least 2GB]"
    )
