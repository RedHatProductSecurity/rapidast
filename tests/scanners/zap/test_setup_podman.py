from pathlib import Path

import pytest

import configmodel.converter
from scanners.zap.zap import find_context
from scanners.zap.zap_podman import ZapPodman

# from pytest_mock import mocker

CONFIG_TEMPLATE_LONG = "config/config-template-long.yaml"


@pytest.fixture(scope="function")
def test_config():
    return configmodel.RapidastConfigModel(
        {"application": {"url": "http://example.com"}}
    )


## Basic test


def test_setup_basic(test_config):
    test_zap = ZapPodman(config=test_config)
    test_zap.setup()

    # a '/' should have been appended
    assert (
        test_zap.automation_config["env"]["contexts"][0]["urls"][0]
        == "http://example.com/"
    )


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


def test_setup_authentication_http_header(test_config):
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
    assert (
        "ZAP_AUTH_HEADER_VALUE=mycookiename=mycookieval"
        in test_zap.podman.get_complete_cli()
    )


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
        in test_zap.podman.get_complete_cli()
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
    assert "RTOKEN" in test_zap.podman.get_complete_cli()
    assert (
        test_zap.automation_config["jobs"][0]["parameters"]["name"]
        == "add-bearer-token"
    )


## Testing APIs & URLs ##


def test_setup_import_urls(test_config):
    # trick: set this very file as import
    test_config.set("scanners.zap.importUrlsFromFile", __file__)

    test_zap = ZapPodman(config=test_config)
    test_zap.setup()
    assert Path(test_zap.host_work_dir, "importUrls.txt").is_file()


def test_setup_exclude_urls(test_config):
    test_config.set("scanners.zap.urls.excludes", ["abc", "def"])
    test_config.merge(
        test_config.get("general", default={}), preserve=False, root=f"scanners.zap"
    )

    test_zap = ZapPodman(config=test_config)
    test_zap.setup()

    assert "abc" in find_context(test_zap.automation_config)["excludePaths"]
    assert "def" in find_context(test_zap.automation_config)["excludePaths"]


def test_setup_include_urls(test_config):
    test_config.set("scanners.zap.urls.includes", ["abc", "def"])
    test_config.merge(
        test_config.get("general", default={}), preserve=False, root=f"scanners.zap"
    )

    test_zap = ZapPodman(config=test_config)
    test_zap.setup()

    assert "abc" in find_context(test_zap.automation_config)["includePaths"]
    assert "def" in find_context(test_zap.automation_config)["includePaths"]


def test_setup_ajax(test_config):
    test_config.set("scanners.zap.spiderAjax.maxDuration", 10)
    test_config.set("scanners.zap.spiderAjax.url", "http://test.com")
    test_config.set("scanners.zap.spiderAjax.browserId", "chrome-headless")

    test_zap = ZapPodman(config=test_config)
    test_zap.setup()

    for item in test_zap.automation_config["jobs"]:
        if item["type"] == "spiderAjax":
            assert item["parameters"]["maxDuration"] == 10
            assert item["parameters"]["url"] == "http://test.com"
            assert item["parameters"]["browserId"] == "chrome-headless"
            break
    else:
        assert False


def test_setup_graphql(test_config):
    TEST_GRAPHQL_ENDPOINT = "http://test.com/graphql"
    TEST_GRAPHQL_SCHEMA_URL = "http://test.com/schema.graphql"

    test_config.set("scanners.zap.graphql.endpoint", TEST_GRAPHQL_ENDPOINT)
    test_config.set("scanners.zap.graphql.schemaUrl", TEST_GRAPHQL_SCHEMA_URL)
    test_config.set("scanners.zap.graphql.schemaFile", __file__)

    test_zap = ZapPodman(config=test_config)
    test_zap.setup()

    for item in test_zap.automation_config["jobs"]:
        if item["type"] == "graphql":
            assert item["parameters"]["endpoint"] == TEST_GRAPHQL_ENDPOINT
            assert item["parameters"]["schemaUrl"] == TEST_GRAPHQL_SCHEMA_URL
            assert (
                item["parameters"]["schemaFile"]
                == f"{test_zap.container_work_dir}/schema.graphql"
            )
            break
    else:
        assert False, "graphql job not found"


def test_setup_pod_injection(test_config):
    test_config.set("scanners.zap.container.parameters.podName", "podABC")

    test_zap = ZapPodman(config=test_config)
    test_zap.setup()

    assert "--pod" in test_zap.podman.get_complete_cli()
    assert "podABC" in test_zap.podman.get_complete_cli()

    # Also assert that there is no uid mapping
    assert not "--uidmap" in test_zap.podman.get_complete_cli()


## Testing report format ##


@pytest.mark.parametrize(
    "result_format, expected_template",
    [
        ("html", "traditional-html-plus"),
        ("json", "traditional-json-plus"),
        ("sarif", "sarif-json"),
        ("xml", "traditional-xml-plus"),
    ],
)
def test_setup_report_format(test_config, result_format, expected_template):
    test_config.set("scanners.zap.report.format", [result_format])

    print(test_config)

    test_zap = ZapPodman(config=test_config)
    test_zap.setup()

    for item in test_zap.automation_config["jobs"]:
        if item["type"] == "report":
            assert item["parameters"]["template"] == expected_template
            break
    else:
        assert False


# Misc tests


def test_override_memory_allocation(test_config):
    # "regular" test
    test_config.set("scanners.zap.miscOptions.memMaxHeap", "8G")
    test_zap = ZapPodman(config=test_config)
    test_zap.setup()
    assert "-Xmx8G" in test_zap.zap_cli

    # Fail match
    test_config.set("scanners.zap.miscOptions.memMaxHeap", "8i")
    test_zap = ZapPodman(config=test_config)
    test_zap.setup()
    assert "-Xmx8i" not in test_zap.zap_cli
