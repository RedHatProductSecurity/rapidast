import os

import pytest

import configmodel
import rapidast
from scanners.garak.garak_none import Garak


@pytest.fixture(scope="function")
def test_config():
    return configmodel.RapidastConfigModel()


def test_setup_garak(test_config):
    test_config.set("scanners.generic.inline", "tmp_cmd")

    config_data = rapidast.load_config("config/config-template-garak.yaml")
    test_config = configmodel.RapidastConfigModel(config_data)

    test_model_name = "testname"
    test_model_type = "testtype"
    test_probe_spec = "dan.Dan_11_0"

    test_garak_config_in_rapidast = {
        "model_name": test_model_name,
        "model_type": test_model_type,
        "probe_spec": test_probe_spec,
    }

    test_config.set("scanners.garak", test_garak_config_in_rapidast)

    test_garak = Garak(config=test_config)
    test_garak.setup()

    assert test_garak.automation_config["plugins"]["model_name"] == test_model_name
    assert test_garak.automation_config["plugins"]["model_type"] == test_model_type
    assert test_garak.automation_config["plugins"]["probe_spec"] == test_probe_spec

    assert test_garak.garak_cli
    assert test_garak.garak_cli[:3] == [
        test_garak.cfg.garak_executable_path,
        "--config",
        os.path.join(test_garak.workdir, test_garak.GARAK_RUN_CONFIG_FILE),
    ]
