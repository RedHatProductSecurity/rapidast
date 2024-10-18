import pytest
import yaml
from unittest.mock import patch, mock_open

from rapidast import dump_redacted_config, DEFAULT_CONFIG_FILE

@pytest.fixture
def mock_yaml_data() -> dict:
    return {
        'service1': {
            'authentication': {
                'parameters': {
                    'username': 'admin',
                    'password': 'secret'
                }
            }
        },
        'service2': {
            'authentication': {
                'parameters': {
                    'api_key': '123456'
                }
            }
        }
    }

@patch('yaml.safe_load')
@patch('yaml.dump')
@patch('os.path.exists')
@patch('shutil.copy')
@patch('builtins.open', new_callable=mock_open)
@patch("rapidast.load_config_file")
def test_dump_redacted_config_success(mock_load_config_file, mock_open_func, mock_copy, mock_exists, mock_yaml_dump, mock_yaml_load, mock_yaml_data: dict) -> None:
    
    
    expected_redacted_data = {
        'service1': {
            'authentication': {
                'parameters': {
                    'username': '*****',
                    'password': '*****'
                }
            }
        },
        'service2': {
            'authentication': {
                'parameters': {
                    'api_key': '*****'
                }
            }
        }
    }
    mock_exists.return_value = True
    mock_yaml_load.return_value = mock_yaml_data
    success = dump_redacted_config('config.yaml', 'destination_dir')
    
    assert success
    mock_exists.assert_called_once_with(DEFAULT_CONFIG_FILE)
    mock_copy.assert_called_once_with(DEFAULT_CONFIG_FILE, 'destination_dir')

    mock_open_func.assert_called_once_with('destination_dir/config.yaml', 'w', encoding='utf-8')
    mock_yaml_dump.assert_called_once_with(expected_redacted_data, mock_open_func())
      
@patch("rapidast.load_config_file")
def test_dump_redacted_exceptions(mock_load_config_file) -> None:
    
    for e in (FileNotFoundError, yaml.YAMLError, IOError):
        mock_load_config_file.side_effect = e
        success = dump_redacted_config('invalid_config.yaml', 'destination_dir')
        assert not success