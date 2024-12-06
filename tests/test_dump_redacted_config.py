from unittest.mock import mock_open
from unittest.mock import patch

import pytest
import yaml

from rapidast import DEFAULT_CONFIG_FILE
from rapidast import dump_rapidast_redacted_configs
from rapidast import dump_redacted_config


@pytest.fixture
def mock_yaml_data() -> dict:
    return {
        "service1": {"authentication": {"parameters": {"username": "admin", "password": "secret"}}},
        "service2": {"authentication": {"parameters": {"api_key": "123456"}}},
    }


@patch("yaml.safe_load")
@patch("yaml.dump")
@patch("builtins.open", new_callable=mock_open)
@patch("rapidast.load_config_file")
def test_dump_redacted_config_success(
    mock_load_config_file, mock_open_func, mock_yaml_dump, mock_yaml_load, mock_yaml_data: dict
) -> None:
    expected_redacted_data = {
        "service1": {"authentication": {"parameters": {"username": "*****", "password": "*****"}}},
        "service2": {"authentication": {"parameters": {"api_key": "*****"}}},
    }
    mock_yaml_load.return_value = mock_yaml_data
    success = dump_redacted_config("config.yaml", "destination_dir")

    assert success

    mock_open_func.assert_called_once_with("destination_dir/config.yaml", "w", encoding="utf-8")
    mock_yaml_dump.assert_called_once_with(expected_redacted_data, mock_open_func())


@patch("rapidast.load_config_file")
def test_dump_redacted_exceptions(mock_load_config_file) -> None:
    for e in (FileNotFoundError, yaml.YAMLError, IOError):
        mock_load_config_file.side_effect = e
        success = dump_redacted_config("invalid_config.yaml", "destination_dir")
        assert not success


@patch("os.makedirs")
@patch("os.path.exists")
@patch("rapidast.load_config_file")
def test_dump_redacted_config_creates_destination_dir(mock_load_config_file, mock_exists, mock_os_makedirs) -> None:
    # Raising a FileNotFoundError to simulate the absence of the configuration file and stop the process
    mock_load_config_file.side_effect = FileNotFoundError
    mock_exists.return_value = False
    _ = dump_redacted_config("config.yaml", "destination_dir")

    mock_os_makedirs.assert_called_with("destination_dir")


@patch("os.path.exists")
@patch("rapidast.dump_redacted_config")
def test_dump_rapidast_redacted_configs(mock_dump_redacted_config, mock_exists):
    mock_exists.return_value = True
    dump_rapidast_redacted_configs("config.yaml", "destination_dir")

    mock_exists.assert_called_once_with(DEFAULT_CONFIG_FILE)
    mock_dump_redacted_config.assert_any_call(DEFAULT_CONFIG_FILE, "destination_dir")
    mock_dump_redacted_config.assert_any_call("config.yaml", "destination_dir")
