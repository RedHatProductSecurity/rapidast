import logging
import os
from unittest.mock import patch

import pytest

from scanners.generic.tools import oobtkube

TEST_DATA_DIR = "tests/scanners/generic/tools/test_data_oobtkube/"


@pytest.fixture
def test_data():
    # Sample nested dictionary data for testing
    return {
        "root": {
            "branch": {"leaf1": "value1", "spec": {"leaf2": "value2"}},
            "leaf3": "value3",
        }
    }


def test_count_total_leaf_keys(test_data):
    # Test if the count_leaf_keys function returns the correct count of leaf keys
    assert oobtkube.count_total_leaf_keys(test_data) == 3


@patch("scanners.generic.tools.oobtkube.os.system")
def test_find_leaf_keys_and_test(mock_system, test_data, caplog):
    """
    Ensure all the leaves are navigated through
    """

    caplog.set_level(logging.INFO)

    total_leaf_keys = oobtkube.count_total_leaf_keys(test_data)

    oobtkube.find_leaf_keys_and_test(test_data, "cr_test_file", "10.10.10.10", "12345", total_leaf_keys)

    processed_count = 0
    leaves = ["leaf1", "leaf2", "leaf3"]
    for leaf_key in leaves:
        processed_count += 1
        assert f"Testing a leaf key: '{leaf_key}', ({processed_count} / {total_leaf_keys})" in caplog.text

    assert mock_system.call_count == 6  # Each leaf key runs `sed` and `kubectl` commands (2 calls per key)


def test_parse_resource_yaml():
    path = os.path.join(TEST_DATA_DIR, "pod.yaml")
    obj_data = oobtkube.parse_obj_data(path)
    assert obj_data["kind"] == "Pod"
    assert isinstance(obj_data["spec"], dict)
    assert isinstance(obj_data["metadata"], dict)
