import pytest
import yaml

import configmodel.converter
from scanners.zap.zap_podman import ZapPodman

# from pytest_mock import mocker

CONFIG_TEMPLATE_LONG = "config/config-template-long.yaml"


@pytest.fixture(scope="function")
def test_config():
    return configmodel.RapidastConfigModel()


def test_setup_authentication_no_auth_configured(test_config):
    print(test_config.get("general"))

    test_zap = ZapPodman(config=test_config)
    test_zap.setup()
    assert test_zap.authenticated == False


def test_setup_authentication_invalid_auth_configured(test_config):
    authentication = {"type": "invalid", "parameters": {"dummy": "value"}}

    test_config.set("general.authentication", authentication)

    test_config.merge(
        test_config.get("general", default={}), preserve=False, root=f"scanners.zap"
    )

    print(test_config)

    test_zap = ZapPodman(config=test_config)
    test_zap.setup()
    assert test_zap.authenticated == False


def test_setup_authentication_auth_rtoken_configured(test_config):
    # with open(CONFIG_TEMPLATE_LONG) as f:
    #    test_config = configmodel.RapidastConfigModel(
    #        yaml.safe_load(f)
    #    )

    authentication = {
        "type": "oauth2_rtoken",
        "parameters": {
            "client_id": "cloud-services",
            "token_endpoint": "<token retrieval URL>",
            "rtoken_var_name": "RTOKEN",
        },
    }

    test_config.set("general.authentication", authentication)

    test_config.merge(
        test_config.get("general", default={}), preserve=False, root=f"scanners.zap"
    )

    print(test_config)

    test_zap = ZapPodman(config=test_config)

    test_zap.setup()
    assert test_zap.authenticated == True
