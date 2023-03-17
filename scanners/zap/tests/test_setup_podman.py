import pytest
import yaml

import configmodel.converter
from scanners.zap.zap_podman import ZapPodman

# from pytest_mock import mocker

CONFIG_TEMPLATE_LONG = "config/config-template-long.yaml"


@pytest.fixture(scope="function")
def test_config():
    return configmodel.RapidastConfigModel()


## Testing files and paths ##


def test_path_translation_host_2_container(test_config):
    test_zap = ZapPodman(config=test_config)
    test_zap._add_volume("/q/w/e/r/t", "/y/u/i/o/p")
    test_zap._add_volume("/a/s/d/f/g", "/h/j/k/l")
    test_zap._add_volume("/z/x/c/v", "/b/n/m")

    assert test_zap._paths_h2c("/a/s/d/f/g/subdir/myfile") == "/h/j/k/l/subdir/myfile"

    assert test_zap._paths_c2h("/b//n/m/subdir/myfile") == "/z/x/c/v/subdir/myfile"


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
