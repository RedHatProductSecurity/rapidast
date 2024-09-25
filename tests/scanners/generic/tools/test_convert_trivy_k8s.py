# test_convert_trivy_k8s_to_sarif.py
import json

import pytest

from scanners.generic.tools.convert_trivy_k8s_to_sarif import convert_json_to_sarif, read_json_block

TEST_DATA_DIR = "tests/scanners/generic/tools/test_data_convert_trivy_k8s/"


def _assert_default_sarif_info(sarif):
    print(sarif)

    if sarif["runs"][0]["tool"]["driver"]["name"] != "Trivy-k8s":
        return False

    if sarif["version"] != "2.1.0":
        return False

    return True

def test_read_json_block():
    json_file = TEST_DATA_DIR + "sample-single-result.json"
    json_assert = json.load(open(json_file))

    json_test = read_json_block(json_file)
    assert json_test == json_assert


def test_convert_json_to_sarif():
    json_file = TEST_DATA_DIR + "sample-single-result.json"
    json_data = json.load(open(json_file))

    sarif = convert_json_to_sarif(json_data)
    assert _assert_default_sarif_info(sarif)
    assert len(sarif["runs"][0]["results"]) == 1

    json_file = TEST_DATA_DIR + "sample-multiple-results.json"
    json_data = json.load(open(json_file))

    sarif = convert_json_to_sarif(json_data)
    assert _assert_default_sarif_info(sarif)
    assert len(sarif["runs"][0]["results"]) > 1
    assert sarif["runs"][0]["results"][0]["ruleId"] == "KSV001"
    assert sarif["runs"][0]["results"][1]["ruleId"] == "KSV002"


def test_no_misconfiguration_finding():
    # no misconfiguration
    json_file = TEST_DATA_DIR + "sample-no-misconfig-finding.json"
    with open(json_file, "r", encoding="utf-8") as f:
        json_data = json.load(f)

    sarif = convert_json_to_sarif(json_data)
    assert _assert_default_sarif_info(sarif)
    assert len(sarif["runs"][0]["results"]) == 0


def test_empty_json():
    json_data = json.loads("{}")
    assert _assert_default_sarif_info(convert_json_to_sarif(json_data))

    json_data = json.loads("[]")
    assert _assert_default_sarif_info(convert_json_to_sarif(json_data))
