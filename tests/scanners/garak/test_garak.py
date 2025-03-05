import os
from unittest.mock import patch

import pytest

import configmodel
import rapidast
from scanners.garak.garak_none import Garak


@pytest.fixture(scope="function")
def test_config():
    return configmodel.RapidastConfigModel()


# Mock the _check_garak_version method for the test to run successfully where Garak is not installed
@patch("scanners.garak.garak_none.Garak._check_garak_version")
def test_setup_garak(mock_check_garak_version, test_config):
    mock_check_garak_version.return_value = None
    config_data = rapidast.load_config("config/config-template-garak.yaml")
    test_config = configmodel.RapidastConfigModel(config_data)

    test_model_name = "testname"
    test_model_type = "testtype"
    test_probe_spec = "dan.Dan_11_0"
    test_generators = {
        "rest": {
            "uri": "https://stage.test.com/api/",
            "method": "POST",
            "response_json_field": "text",
        }
    }

    test_garak_config_in_rapidast = {
        "garak_config": {
            "plugins": {
                "model_name": test_model_name,
                "model_type": test_model_type,
                "probe_spec": test_probe_spec,
                "generators": test_generators,
            }
        }
    }

    test_config.set("scanners.garak", test_garak_config_in_rapidast)

    test_garak = Garak(config=test_config)
    test_garak.setup()

    assert test_garak.automation_config["plugins"]["model_name"] == test_model_name
    assert test_garak.automation_config["plugins"]["model_type"] == test_model_type
    assert test_garak.automation_config["plugins"]["probe_spec"] == test_probe_spec
    assert test_garak.automation_config["plugins"]["generators"] == test_generators

    assert test_garak.garak_cli
    assert test_garak.garak_cli[:3] == [
        test_garak.cfg.garak_executable_path,
        "--config",
        os.path.join(test_garak.workdir, test_garak.GARAK_RUN_CONFIG_FILE),
    ]
