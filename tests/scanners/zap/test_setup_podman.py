import re
from pathlib import Path

import pytest
import requests

import configmodel
from scanners.zap.zap import find_context
from scanners.zap.zap_podman import ZapPodman

# from pytest_mock import mocker

CONFIG_TEMPLATE_LONG = "config/config-template-long.yaml"


@pytest.fixture(scope="function")
def test_config():
    return configmodel.RapidastConfigModel(
        {"application": {"url": "http://example.com"}}
    )


## Testing Authentication methods ##
### Handling Authentication is different depending on the container.type so it'd be better to have test cases separately


def test_setup_podman_authentication_invalid_auth_configured(test_config):
    authentication = {"type": "invalid", "parameters": {"dummy": "value"}}

    test_config.set("general.authentication", authentication)

    test_config.merge(
        test_config.get("general", default={}), preserve=False, root=f"scanners.zap"
    )

    print(test_config)

    test_zap = ZapPodman(config=test_config)

    # Currently, misconfigured authentication type is expected to raise exception
    with pytest.raises(Exception) as e_info:
        test_zap.setup()


def test_setup_podman_authentication_http_header(test_config):
    authentication = {
        "type": "http_header",
        "parameters": {"name": "myheadername", "value": "myheaderval"},
    }
    test_config.set("general.authentication", authentication)

    test_config.merge(
        test_config.get("general", default={}), preserve=False, root=f"scanners.zap"
    )

    print(test_config)

    test_zap = ZapPodman(config=test_config)
    test_zap.setup()
    assert test_zap.authenticated == False
    assert "ZAP_AUTH_HEADER_VALUE=myheaderval" in test_zap.podman.get_complete_cli()
    assert "ZAP_AUTH_HEADER=myheadername" in test_zap.podman.get_complete_cli()


def test_setup_podman_authentication_cookie(test_config):
    authentication = {
        "type": "cookie",
        "parameters": {"name": "mycookiename", "value": "mycookieval"},
    }
    test_config.set("general.authentication", authentication)

    test_config.merge(
        test_config.get("general", default={}), preserve=False, root=f"scanners.zap"
    )

    print(test_config)

    test_zap = ZapPodman(config=test_config)
    test_zap.setup()
    assert test_zap.authenticated == False
    assert (
        "ZAP_AUTH_HEADER_VALUE=mycookiename=mycookieval"
        in test_zap.podman.get_complete_cli()
    )


def test_setup_podman_authentication_http_basic(test_config):
    authentication = {
        "type": "http_basic",
        "parameters": {"username": "Aladdin", "password": "open sesame"},
    }
    test_config.set("general.authentication", authentication)

    test_config.merge(
        test_config.get("general", default={}), preserve=False, root=f"scanners.zap"
    )

    print(test_config)

    test_zap = ZapPodman(config=test_config)
    test_zap.setup()
    assert test_zap.authenticated == False
    assert (
        "ZAP_AUTH_HEADER_VALUE=Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="
        in test_zap.podman.get_complete_cli()
    )


def test_setup_podman_authentication_auth_rtoken_configured(test_config):
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
    assert "RTOKEN" in test_zap.podman.get_complete_cli()
    assert (
        test_zap.automation_config["jobs"][0]["parameters"]["name"]
        == "add-bearer-token"
    )


def test_setup_podman_authentication_auth_rtoken_preauth(test_config):
    # Verify that preauth changes the oauth2_rtoken to http_header
    authentication = {
        "type": "oauth2_rtoken",
        "parameters": {
            "client_id": "cloud-services",
            "token_endpoint": "<token retrieval URL>",
            "rtoken_var_name": "RTOKEN",
            "preauth": True,
        },
    }

    test_config.set("general.authentication", authentication)

    test_config.merge(
        test_config.get("general", default={}), preserve=False, root=f"scanners.zap"
    )

    test_zap = ZapPodman(config=test_config)

    with pytest.raises(requests.exceptions.MissingSchema) as e_info:
        test_zap.setup()
    assert "Invalid URL '<token retrieval URL>'" in str(e_info.value)


## Testing APIs & URLs ##


def test_setup_podman_pod_injection(test_config):
    test_config.set("scanners.zap.container.parameters.podName", "podABC")

    test_zap = ZapPodman(config=test_config)
    test_zap.setup()

    assert "--pod" in test_zap.podman.get_complete_cli()
    assert "podABC" in test_zap.podman.get_complete_cli()

    # Also assert that there is no uid mapping
    assert not "--uidmap" in test_zap.podman.get_complete_cli()


# Misc tests


def test_podman_handling_ajax(test_config):
    test_config.set("scanners.zap.spiderAjax.url", "https://abcdef.jklm")
    test_zap = ZapPodman(config=test_config)
    # create a fake automation framework: just an empty `jobs` is sufficient
    test_zap.automation_config = {"jobs": []}
    test_zap._setup_ajax_spider()

    cli = test_zap.podman.get_complete_cli()
    i = cli.index("--shm-size")
    assert cli[i + 1] == "2g"
    i = cli.index("--pids-limit")
    assert cli[i + 1] == "-1"


def test_podman_handling_plugins(test_config):
    test_config.set("scanners.zap.miscOptions.updateAddons", True)
    test_config.set("scanners.zap.miscOptions.additionalAddons", "pluginA,pluginB")
    test_zap = ZapPodman(config=test_config)

    assert "-addonupdate" in test_zap.get_update_command()
    assert "pluginA" in test_zap.get_update_command()
    assert "pluginB" in test_zap.get_update_command()

    shell = test_zap._handle_plugins()
    assert len(shell) == 3
    assert shell[0] == "sh"
    assert shell[1] == "-c"
    assert re.search(
        "^zap.sh .* -cmd -addonupdate -addoninstall pluginA -addoninstall pluginB; .*",
        shell[2],
    )
