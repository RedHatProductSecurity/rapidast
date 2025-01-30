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
        "apiVersion": "v1",
        "kind": "Foo",
        "metadata": {"name": "foo"},
        "root": {
            "branch": {"leaf1": "value1", "spec": {"leaf2": "value2"}},
            "leaf3": "value3",
            "branch2": [{"leaf4": "value4"}, {"leaf5": "value5"}],
        },
    }


@patch("scanners.generic.tools.oobtkube.os.system")
def test_find_leaf_keys_and_test(mock_system, test_data, caplog):
    """
    Ensure all the leaves are tested with the payload
    """

    caplog.set_level(logging.INFO)

    oobtkube.find_leaf_keys_and_test(test_data, "10.10.10.10", 12345)

    leaves = [
        "root.branch.leaf1",
        "root.branch.spec.leaf2",
        "root.leaf3",
        "root.branch2.0.leaf4",
        "root.branch2.1.leaf5",
    ]
    for i, leaf_key in enumerate(leaves):
        assert f"Testing leaf key ({i+1} / {len(leaves)}): {leaf_key}" in caplog.text

    assert mock_system.call_count == len(leaves)  # Each leaf key runs a `kubectl` command


def test_parse_resource_yaml():
    path = os.path.join(TEST_DATA_DIR, "pod.yaml")
    obj_data = oobtkube.parse_obj_data(path)
    assert obj_data["kind"] == "Pod"
    assert isinstance(obj_data["spec"], dict)
    assert isinstance(obj_data["metadata"], dict)
