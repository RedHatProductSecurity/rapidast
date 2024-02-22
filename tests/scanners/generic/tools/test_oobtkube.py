import re
from unittest.mock import Mock
from unittest.mock import patch

import pytest

from scanners.generic.tools import oobtkube


@patch("scanners.generic.tools.oobtkube.os.system")
def test_find_leaf_keys_and_test(mock_system):
    data = {
        "root": {
            "branch": {
                "leaf1": 0,
            },
            "leaf2": 1,
        }
    }
    leaves = ["leaf1", "leaf2"]

    def cmd_check(cmd):
        print(f"mock: command: {cmd}")
        if cmd.startswith("kubectl"):
            # ignore these calls, they are static
            return 0
        elif cmd.startswith("sed"):
            # in `sed 's/{key}:.*/{key}: `, extract the value of `key`
            key = re.search(r"sed 's/(.+):\.\*/\1: ", cmd).group(1)
            leaves.remove(key)
        else:
            raise ValueError("system call with bad command")

    mock_system.side_effect = cmd_check

    oobtkube.find_leaf_keys_and_test(data, "xxx", "yyy", "zzz")
    assert not leaves
