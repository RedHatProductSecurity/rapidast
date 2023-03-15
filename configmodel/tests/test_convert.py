import pytest
import yaml

import configmodel.converter


@pytest.fixture(name="config_v0")
def generate_config_v0():
    try:
        with open("config/older-schemas/v0.yaml") as file:
            config = configmodel.RapidastConfigModel(yaml.safe_load(file))
    except yaml.YAMLError as exc:
        raise RuntimeError("Unable to load TEST file v0.yaml") from exc

    return config


def test_v0_to_v1(config_v0):
    conf_v1 = configmodel.converter.convert_from_version_0_to_1(config_v0)

    assert conf_v1.get("application.shortName", "x") == config_v0.get(
        "general.serviceName", "y"
    )
    assert conf_v1.get("scanners.zap.activeScan.policy", "x") == config_v0.get(
        "scan.policies.scanPolicyName", "y"
    )


def test_basic_config_updater():
    """Basic test: from an empty config, after update, we should get the following:
    `config.get("config.configVersion") == CURR_CONFIG_VERSION`

    This test makes sure the config updater runs through all updater functions
    """

    oldest = configmodel.RapidastConfigModel({})
    last = configmodel.converter.update_to_latest_config(oldest)

    assert (
        int(last.get("config.configVersion"))
        == configmodel.converter.CURR_CONFIG_VERSION
    )


if __name__ == "__main__":
    test_basic_config_updater()
