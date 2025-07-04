import os
from pathlib import Path
from unittest.mock import patch

import dacite
import pytest
import requests

from scanners.zap.zap import find_context
from scanners.zap.zap import MODULE_DIR
from scanners.zap.zap_none import ZapNone

# from pytest_mock import mocker

CONFIG_TEMPLATE_LONG = "config/config-template-long.yaml"

## Basic test


def test_setup_openapi(test_config):
    test_zap = ZapNone(config=test_config)
    test_zap.setup()

    # a '/' should have been appended
    assert test_zap.automation_config["env"]["contexts"][0]["urls"][0] == "http://example.com/"

    for item in test_zap.automation_config["jobs"]:
        if item["type"] == "openapi":
            assert item["parameters"]["targetUrl"] == "http://example.com/"
            break

    # Test that a passive scan is added with all rules actively disabled
    for item in test_zap.automation_config["jobs"]:
        if item["type"] == "passiveScan-config":
            assert item["parameters"]["disableAllRules"] == True
            break
    else:
        assert False


def test_setup_no_api_config(test_config):
    # test ValueError is raised when neither apiUrl nor apiFile exists
    test_config.set("scanners.zap.apiScan", "target")

    with pytest.raises(dacite.exceptions.WrongTypeError):
        _ = ZapNone(config=test_config)

    # the following must not raise error as apiUrl has been now defined
    test_config.set("scanners.zap.apiScan.apis.apiUrl", "http://random.com")
    test_zap = ZapNone(config=test_config)

    test_zap.setup()

    test_config.set("scanners.zap.apiScan.apis.apiFile", "api_file")
    test_zap = ZapNone(config=test_config)

    test_zap.setup()

    # openapi job is not added when no openapi config exists
    test_config.delete("scanners.zap.apiScan")
    test_zap = ZapNone(config=test_config)

    test_zap.setup()

    for item in test_zap.automation_config["jobs"]:
        assert item["type"] != "openapi"

    # Test that either 'apiUrl' or 'apiFile' are provided
    test_config.set("scanners.zap.apiScan.apis", {})
    with pytest.raises(ValueError):
        _ = ZapNone(config=test_config)


## Testing Authentication methods ##
### Handling Authentication is different depending on the container.type so it'd be better to have test cases separately


def test_setup_authentication_no_auth_configured(test_config):
    print(test_config.get("general"))

    test_zap = ZapNone(config=test_config)
    test_zap.setup()
    assert test_zap.authenticated == False


def test_setup_authentication_invalid_auth_configured(test_config):
    authentication = {"type": "invalid", "parameters": {"dummy": "value"}}

    test_config.set("general.authentication", authentication)

    test_config.merge(test_config.get("general", default={}), preserve=False, root=f"scanners.zap")

    print(test_config)

    test_zap = ZapNone(config=test_config)

    # Currently, misconfigured authentication type is expected to raise exception
    with pytest.raises(Exception) as e_info:
        test_zap.setup()


def test_setup_authentication_http_header(test_config):
    authentication = {
        "type": "http_header",
        "parameters": {"name": "myheadername", "value": "myheaderval"},
    }
    test_config.set("general.authentication", authentication)

    test_config.merge(test_config.get("general", default={}), preserve=False, root=f"scanners.zap")

    print(test_config)

    test_zap = ZapNone(config=test_config)
    test_zap.setup()
    assert test_zap.authenticated == False
    assert os.environ["ZAP_AUTH_HEADER"] == "myheadername"
    assert os.environ["ZAP_AUTH_HEADER_VALUE"] == "myheaderval"


def test_setup_authentication_cookie(test_config):
    authentication = {
        "type": "cookie",
        "parameters": {"name": "mycookiename", "value": "mycookieval"},
    }
    test_config.set("general.authentication", authentication)

    test_config.merge(test_config.get("general", default={}), preserve=False, root=f"scanners.zap")

    print(test_config)

    test_zap = ZapNone(config=test_config)
    test_zap.setup()
    assert test_zap.authenticated == False
    assert os.environ["ZAP_AUTH_HEADER_VALUE"] == "mycookiename=mycookieval"


def test_setup_authentication_http_basic(test_config):
    authentication = {
        "type": "http_basic",
        "parameters": {"username": "Aladdin", "password": "open sesame"},
    }
    test_config.set("general.authentication", authentication)

    test_config.merge(test_config.get("general", default={}), preserve=False, root=f"scanners.zap")

    print(test_config)

    test_zap = ZapNone(config=test_config)
    test_zap.setup()
    assert test_zap.authenticated == False
    assert os.environ["ZAP_AUTH_HEADER_VALUE"] == "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="


def test_setup_authentication_auth_rtoken_configured(test_config):
    authentication = {
        "type": "oauth2_rtoken",
        "parameters": {
            "client_id": "cloud-services",
            "token_endpoint": "<token retrieval URL>",
            "rtoken_var_name": "RTOKEN",
        },
    }

    test_config.set("general.authentication", authentication)

    test_config.merge(test_config.get("general", default={}), preserve=False, root=f"scanners.zap")

    print(test_config)

    test_zap = ZapNone(config=test_config)

    test_zap.setup()
    assert test_zap.authenticated == True
    # TODO: check "RTOKEN"
    assert test_zap.automation_config["jobs"][0]["parameters"]["name"] == "add-bearer-token"


def test_setup_authentication_auth_rtoken_preauth(test_config):
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

    test_config.merge(test_config.get("general", default={}), preserve=False, root=f"scanners.zap")

    test_zap = ZapNone(config=test_config)

    with pytest.raises(requests.exceptions.MissingSchema) as e_info:
        test_zap.setup()
    assert "Invalid URL '<token retrieval URL>'" in str(e_info.value)


def test_setup_authentication_auth_browser(test_config):
    authentication = {
        "type": "browser",
        "parameters": {
            "loginPageUrl": "http://example.com/login",
            "verifyUrl": "/verify",
            "username": "usern",
            "password": "pass",
            "loginPageWait": "3",
            "loggedInRegex": "\\Q 200 OK\\E",
            "loggedOutRegex": "\\Q 401 Unauthorized\\E",
        },
    }

    test_config.set("general.authentication", authentication)
    test_config.merge(test_config.get("general", default={}), preserve=False, root=f"scanners.zap")
    test_zap = ZapNone(config=test_config)
    test_zap.setup()

    assert test_zap.authenticated == True
    assert test_zap.automation_config["env"]["contexts"][0]["authentication"] == {
        "method": "browser",
        "parameters": {
            "browserId": "firefox-headless",
            "loginPageUrl": "http://example.com/login",
            "loginPageWait": "3",
        },
        "verification": {
            "loggedInRegex": "\\Q 200 OK\\E",
            "loggedOutRegex": "\\Q 401 Unauthorized\\E",
            "method": "poll",
            "pollFrequency": 60,
            "pollPostData": "",
            "pollUnits": "requests",
            "pollUrl": "http://example.com/verify",
        },
    }


## Testing APIs & URLs ##


def test_setup_import_urls(test_config):
    # trick: use is the current pytest as import file

    # 1- Test importUrlsFromFile, with type "har"
    test_config.set("scanners.zap.importUrlsFromFile", {"type": "har", "fileName": __file__})
    test_zap = ZapNone(config=test_config)
    test_zap.setup()
    for item in test_zap.automation_config["jobs"]:
        if item["type"] == "import":
            assert item["parameters"]["type"] == "har"
            break
    else:
        assert False

    # 2- Test that importUrlsFromFile defaults to "url" type
    test_config.set("scanners.zap.importUrlsFromFile", {"fileName": __file__})
    test_zap = ZapNone(config=test_config)
    test_zap.setup()
    for item in test_zap.automation_config["jobs"]:
        if item["type"] == "import":
            assert item["parameters"]["type"] == "url"
            break
    else:
        assert False

    # 3- Test that importUrlsFromFile fails if the type is incorrect
    test_config.set("scanners.zap.importUrlsFromFile", {"type": "doesntexist", "fileName": __file__})

    with pytest.raises(ValueError) as exc:
        test_zap = ZapNone(config=test_config)

    # 4- Test that importUrlsFromFile fails if the filename is missing
    test_config.set("scanners.zap.importUrlsFromFile", {"type": "har"})

    with pytest.raises(dacite.exceptions.MissingValueError) as exc:
        test_zap = ZapNone(config=test_config)


def test_setup_exclude_urls(test_config):
    test_config.set("scanners.zap.urls.excludes", ["abc", "def"])
    test_config.merge(test_config.get("general", default={}), preserve=False, root=f"scanners.zap")

    test_zap = ZapNone(config=test_config)
    test_zap.setup()

    assert "abc" in find_context(test_zap.automation_config)["excludePaths"]
    assert "def" in find_context(test_zap.automation_config)["excludePaths"]


def test_setup_include_urls(test_config):
    test_config.set("scanners.zap.urls.includes", ["abc", "def"])
    test_config.merge(test_config.get("general", default={}), preserve=False, root=f"scanners.zap")

    test_zap = ZapNone(config=test_config)
    test_zap.setup()

    assert "abc" in find_context(test_zap.automation_config)["includePaths"]
    assert "def" in find_context(test_zap.automation_config)["includePaths"]


def test_setup_replacer_parameter(test_config):
    test_rule = {
        "description": "test_rule1",  # String, the name of the rule
        "url": ".*",  # (optional) String, a regex which will be used to match URLs, if empty then it will match all
        "matchType": "req_body_str",  # String, one of req_header, req_header_str, req_body_str, resp_header, resp_header_str, resp_body_str
        "matchString": "John Doe",  # String, will be used to identify what should be replaced
        "matchRegex": False,  # Boolean, if set then the matchString will be treated as a regex, default false
        "replacementString": "test_string",  # String, the new string that will replace the specified selection
        "tokenProcessing": False,  # (optional) Boolean, when enabled the replacementString may contain a single token
    }

    test_config.set("scanners.zap.replacer.rules", [test_rule])

    test_zap = ZapNone(config=test_config)
    test_zap.setup()

    # test: deleteAllRules is True when it is not set
    for item in test_zap.automation_config["jobs"]:
        if item["type"] == "replacer":
            assert item["parameters"]["deleteAllRules"] is True

    # test: deleteAllRules parameter is set to False
    test_config.set("scanners.zap.replacer.parameters.deleteAllRules", False)
    test_zap = ZapNone(config=test_config)
    test_zap.setup()

    for item in test_zap.automation_config["jobs"]:
        if item["type"] == "replacer":
            assert isinstance(item["parameters"]["deleteAllRules"], bool)
            assert item["parameters"]["deleteAllRules"] is False

    # test: when deleteAllRules parameter is not Boolean type
    test_config.set("scanners.zap.replacer.parameters.deleteAllRules", "non-boolean")
    with pytest.raises(dacite.exceptions.WrongTypeError):
        test_zap = ZapNone(config=test_config)


def test_setup_replacer_rules(test_config):
    # test rules
    test_rule1 = {
        "description": "test_rule1",  # String, the name of the rule
        "url": ".*",  # (optional) String, a regex which will be used to match URLs, if empty then it will match all
        "matchType": "req_body_str",  # String, one of req_header, req_header_str, req_body_str, resp_header, resp_header_str, resp_body_str
        "matchString": "John Doe",  # String, will be used to identify what should be replaced
        "matchRegex": False,  # Boolean, if set then the matchString will be treated as a regex, default false
        "replacementString": "test_string",  # String, the new string that will replace the specified selection
        "tokenProcessing": False,  # (optional) Boolean, when enabled the replacementString may contain a single token
    }
    test_rule2 = {
        "description": "test_rule2",  # String, the name of the rule
        "matchType": "req_header",  # String, one of req_header, req_header_str, req_body_str, resp_header, resp_header_str, resp_body_str
        "matchString": "Cookie",  # String, will be used to identify what should be replaced
        "matchRegex": True,  # Boolean, if set then the matchString will be treated as a regex, default false
        "replacementString": "session=abc123",
    }

    test_config.set("scanners.zap.replacer.rules", [test_rule1, test_rule2])

    test_zap = ZapNone(config=test_config)
    test_zap.setup()

    for item in test_zap.automation_config["jobs"]:
        if item["type"] == "replacer":
            assert item["rules"][0] == test_rule1
            assert isinstance(item["rules"][0]["matchRegex"], bool)
            assert isinstance(item["rules"][0]["tokenProcessing"], bool)

            assert item["rules"][1] == test_rule2
            assert isinstance(item["rules"][1]["matchRegex"], bool)


@patch("scanners.zap.zap.validate_active_scan_policy")
def test_setup_active_scan(mock_validate_active_scan_policy, test_config):
    test_config.set("scanners.zap.activeScan.maxRuleDurationInMins", 10)
    test_zap = ZapNone(config=test_config)
    test_zap.setup()

    for item in test_zap.automation_config["jobs"]:
        if item["type"] == "activeScan":
            assert item["parameters"]["policy"] == "API-scan-minimal"
            assert item["parameters"]["maxRuleDurationInMins"] == 10
            assert item["parameters"]["context"] == "Default Context"
            assert item["parameters"]["user"] == ""
            mock_validate_active_scan_policy.assert_called_once_with(
                policy_path=Path(f"{MODULE_DIR}/policies/API-scan-minimal.policy")
            )

            break
    else:
        assert False


def test_setup_ajax(test_config):
    test_config.set("scanners.zap.spiderAjax.maxDuration", 10)
    test_config.set("scanners.zap.spiderAjax.url", "http://test.com")
    test_config.set("scanners.zap.spiderAjax.browserId", "chrome-headless")
    test_config.set("scanners.zap.spiderAjax.maxCrawlState", 3)

    test_zap = ZapNone(config=test_config)
    test_zap.setup()

    for item in test_zap.automation_config["jobs"]:
        if item["type"] == "spiderAjax":
            assert item["parameters"]["context"] == "Default Context"
            assert item["parameters"]["maxDuration"] == 10
            assert item["parameters"]["user"] == ""
            assert item["parameters"]["url"] == "http://test.com"
            assert item["parameters"]["browserId"] == "chrome-headless"
            assert item["parameters"]["maxCrawlState"] == 3
            break
    else:
        assert False


def test_setup_graphql(test_config):
    TEST_GRAPHQL_ENDPOINT = "http://test.com/graphql"
    TEST_GRAPHQL_SCHEMA_URL = "http://test.com/schema.graphql"

    test_config.set("scanners.zap.graphql.endpoint", TEST_GRAPHQL_ENDPOINT)
    test_config.set("scanners.zap.graphql.schemaUrl", TEST_GRAPHQL_SCHEMA_URL)
    test_config.set("scanners.zap.graphql.schemaFile", __file__)

    test_zap = ZapNone(config=test_config)
    test_zap.setup()

    for item in test_zap.automation_config["jobs"]:
        if item["type"] == "graphql":
            assert item["parameters"]["endpoint"] == TEST_GRAPHQL_ENDPOINT
            assert item["parameters"]["schemaUrl"] == TEST_GRAPHQL_SCHEMA_URL
            assert item["parameters"]["schemaFile"] == f"{test_zap.container_work_dir}/schema.graphql"
            break
    else:
        assert False, "graphql job not found"


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

    test_zap = ZapNone(config=test_config)
    test_zap.setup()

    report_templates = [
        job["parameters"]["template"] for job in test_zap.automation_config["jobs"] if job["type"] == "report"
    ]

    assert expected_template in report_templates, f"{expected_template} not found in {report_templates}"


def test_setup_report_string_format(test_config):
    test_config.set("scanners.zap.report.format", "xml")

    test_zap = ZapNone(config=test_config)
    test_zap.setup()

    count = 0
    for item in test_zap.automation_config["jobs"]:
        if item["type"] == "report":
            assert item["parameters"]["template"] in {
                "traditional-xml-plus",
                "sarif-json",  # Always enabled
            }
            count += 1

    assert count == 2


def test_setup_report_default_formats(test_config):
    test_zap = ZapNone(config=test_config)
    test_zap.setup()

    count = 0
    for item in test_zap.automation_config["jobs"]:
        if item["type"] == "report":
            assert item["parameters"]["template"] in {
                "traditional-json-plus",
                "sarif-json",
            }
            count += 1

    assert count == 2


def test_setup_report_several_formats(test_config):
    test_config.set("scanners.zap.report.format", ["xml", "json"])
    test_zap = ZapNone(config=test_config)
    test_zap.setup()

    count = 0
    for item in test_zap.automation_config["jobs"]:
        if item["type"] == "report":
            assert item["parameters"]["template"] in {
                "traditional-json-plus",
                "traditional-xml-plus",
                "sarif-json",  # Always enabled
            }
            count += 1

    assert count == 3


# Misc tests


def test_setup_override_memory_allocation(test_config):
    # "regular" test
    test_config.set("scanners.zap.miscOptions.memMaxHeap", "8G")
    test_zap = ZapNone(config=test_config)
    test_zap.setup()
    assert "-Xmx8G" in test_zap.zap_cli

    # Fail match
    test_config.set("scanners.zap.miscOptions.memMaxHeap", "8i")
    test_zap = ZapNone(config=test_config)
    test_zap.setup()
    assert "-Xmx8i" not in test_zap.zap_cli


def test_setup_override_cfg(test_config):
    override_cfg1 = "formhandler.fields.field(0).fieldId=namespace"
    override_cfg2 = "formhandler.fields.field(0).value=default"

    test_config.set("scanners.zap.miscOptions.overrideConfigs", [override_cfg1, override_cfg2])
    test_zap = ZapNone(config=test_config)
    test_zap.setup()

    assert f"{override_cfg1}" in test_zap.zap_cli
    assert f"{override_cfg2}" in test_zap.zap_cli

    assert r"formhandler.fields.field\(0\)" in test_zap._zap_cli_list_to_str_for_sh(test_zap.zap_cli)


def test_setup_override_non_list_format(test_config):
    test_config.set("scanners.zap.miscOptions.overrideConfigs", "non-list-item")

    with pytest.raises(dacite.exceptions.WrongTypeError):
        _ = ZapNone(config=test_config)


def test_get_update_command(test_config):
    test_config.set("scanners.zap.miscOptions.updateAddons", True)
    test_config.set("scanners.zap.miscOptions.additionalAddons", "pluginA,pluginB")
    test_zap = ZapNone(config=test_config)

    assert "-addonupdate" in test_zap.get_update_command()
    assert "pluginA" in test_zap.get_update_command()
    assert "pluginB" in test_zap.get_update_command()


# Export Site Tree


def test_setup_export_site_tree(test_config, pytestconfig):
    test_zap = ZapNone(config=test_config)
    test_zap.setup()

    add_script = None
    run_script = None
    add_variable_script = None
    run_variable_script = None

    for item in test_zap.automation_config["jobs"]:
        if item["name"] == "export-site-tree-add":
            add_script = item
        if item["name"] == "export-site-tree-run":
            run_script = item
        if item["name"] == "export-site-tree-filename-global-var-add":
            add_variable_script = item
        if item["name"] == "export-site-tree-filename-global-var-run":
            run_variable_script = item

    assert add_script and run_script and add_variable_script and run_variable_script

    assert add_script["parameters"]["name"] == run_script["parameters"]["name"]
    assert add_script["parameters"]["file"] == f"{pytestconfig.rootpath}/scanners/zap/scripts/export-site-tree.js"
    assert add_script["parameters"]["engine"] == "ECMAScript : Graal.js"

    assert add_variable_script["parameters"]["name"] == run_variable_script["parameters"]["name"]
    assert add_variable_script["parameters"]["inline"]
    assert add_variable_script["parameters"]["engine"] == "ECMAScript : Graal.js"
