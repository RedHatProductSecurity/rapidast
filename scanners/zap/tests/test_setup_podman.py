import yaml

import configmodel.converter
import pytest
from scanners.zap.zap_podman import ZapPodman

# from pytest_mock import mocker

CONFIG_TEMPLATE_LONG = "config/config-template-long.yaml"


@pytest.fixture(scope="function")
def test_config():
    return configmodel.RapidastConfigModel()


## Testing Authentication methods ##


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

    # Currently, misconfigured authentication type is expected to raise exception
    with pytest.raises(Exception) as e_info:
        test_zap.setup()


def test_setup_authentication_cookie(test_config):
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
    assert "ZAP_AUTH_HEADER_VALUE=mycookiename=mycookieval" in test_zap.podman_opts


def test_setup_authentication_http_basic(test_config):
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
        in test_zap.podman_opts
    )


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
    assert "RTOKEN" in test_zap.podman_opts
    assert test_zap.af["jobs"][0]["parameters"]["name"] == "add-bearer-token"


def test_setup_ajax(test_config):
    test_config.set("scanners.zap.spiderAjax.maxDuration", 10)
    test_config.set("scanners.zap.spiderAjax.url", "http://test.com")
    test_config.set("scanners.zap.spiderAjax.browserId", "chrome-headless")

    test_zap = ZapPodman(config=test_config)
    test_zap.setup()

    for item in test_zap.af["jobs"]:
        if item["type"] == "spiderAjax":
            assert item["parameters"]["maxDuration"] == 10
            assert item["parameters"]["url"] == "http://test.com"
            assert item["parameters"]["browserId"] == "chrome-headless"
            break


## Testing report format ##


@pytest.mark.parametrize(
    "result_format, expected_template",
    [
        ("html", "traditional-html-plus"),
        ("json", "traditional-json-plus"),
        ("sarif", "sarif-json"),
    ],
)
def test_setup_report_format(test_config, result_format, expected_template):
    # test_config.set("scanners.zap.report.format[0]", "json")
    test_config.set("scanners.zap.report.format", [result_format])

    print(test_config)

    test_zap = ZapPodman(config=test_config)
    test_zap.setup()

    # print(test_zap.af["jobs"])

    report_job_found = 0
    for item in test_zap.af["jobs"]:
        if item["type"] == "report":
            report_job_found += 1
            assert item["parameters"]["template"] == expected_template
            continue
