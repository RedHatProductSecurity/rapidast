import re

import pytest  # pylint: disable=unused-import

import configmodel
import rapidast

# from pytest_mock import mocker

CONFIG_TEMPLATE_LONG = "config/config-template-long.yaml"


def test_get_full_result_dir_path():
    config = configmodel.RapidastConfigModel()
    config.set("application.shortName", "testApp")
    config.set("config.base_results_dir", "/tmp")

    pattern = re.compile("^/tmp/testApp/DAST-(20[0-9]{6})-([0-9]{6})-RapiDAST-testApp$")

    assert pattern.match(rapidast.get_full_result_dir_path(config))
