from datetime import datetime

import pytest

import configmodel
import rapidast

# from pytest_mock import mocker

CONFIG_TEMPLATE_LONG = "config/config-template-long.yaml"


def test_get_full_result_dir_path():
    config = configmodel.RapidastConfigModel()
    config.set("application.shortName", "testApp")
    config.set("config.base_results_dir", "/tmp")

    scan_time_str = datetime.now().strftime("%Y%m%d-%H%M%S")
    assert (
        rapidast.get_full_result_dir_path(config, scan_time_str)
        == f"/tmp/testApp/DAST-{scan_time_str}-RapiDAST-testApp"
    )
