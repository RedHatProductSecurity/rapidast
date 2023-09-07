import pytest
import yaml

import configmodel.converter


@pytest.fixture(name="config_v0")
def generate_config_v0():
    try:
        with open("tests/configmodel/older-schemas/v0.yaml") as file:
            return configmodel.RapidastConfigModel(yaml.safe_load(file))
    except yaml.YAMLError as exc:
        raise RuntimeError("Unable to load TEST file v0.yaml") from exc


@pytest.fixture(name="config_v1")
def generate_config_v1():
    path = "tests/configmodel/older-schemas/v1.yaml"
    try:
        with open(path) as file:
            return configmodel.RapidastConfigModel(yaml.safe_load(file))
    except yaml.YAMLError as exc:
        raise RuntimeError(f"Unable to load TEST file {path}") from exc


@pytest.fixture(name="config_v2")
def generate_config_v2():
    path = "tests/configmodel/older-schemas/v2.yaml"
    try:
        with open(path) as file:
            return configmodel.RapidastConfigModel(yaml.safe_load(file))
    except yaml.YAMLError as exc:
        raise RuntimeError(f"Unable to load TEST file {path}") from exc


def test_v2_to_v3(config_v2):
    oldconf = config_v2
    newconf = configmodel.converter.convert_from_version_2_to_3(oldconf)

    # Check that new path was created
    assert newconf.get("scanners.zap.miscOptions.updateAddons", "x") == oldconf.get(
        "scanners.zap.updateAddons", "y"
    )
    # Check that old path was deleted
    assert not newconf.exists("scanners.zap.updateAddons")


@pytest.fixture(name="config_v4")
def generate_config_v4():
    path = "tests/configmodel/older-schemas/v4.yaml"
    try:
        with open(path) as file:
            return configmodel.RapidastConfigModel(yaml.safe_load(file))
    except yaml.YAMLError as exc:
        raise RuntimeError(f"Unable to load TEST file {path}") from exc


def test_v4_to_v5(config_v4):
    oldconf = config_v4
    newconf = configmodel.converter.convert_from_version_4_to_5(oldconf)

    # Check that new path was created
    assert newconf.get(
        "scanners.zap.miscOptions.oauth2ManualDownload", "x"
    ) == oldconf.get("scanners.zap.miscOptions.oauth2OpenapiManualDownload", "y")
    # Check that old path was deleted
    assert not newconf.exists("scanners.zap.miscOptions.oauth2OpenapiManualDownload")


def test_v1_to_v2(config_v1):
    oldconf = config_v1
    newconf = configmodel.converter.convert_from_version_1_to_2(oldconf)

    assert newconf.get("scanners.zap.container.parameters.image", "x") == oldconf.get(
        "scanners.zap.container.image", "y"
    )


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
