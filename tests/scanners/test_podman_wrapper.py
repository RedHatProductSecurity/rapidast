import shutil
import pytest
import subprocess

from unittest.mock import patch

from scanners.podman_wrapper import PodmanWrapper


@patch("scanners.podman_wrapper.subprocess.run")
def test_change_user_id(mock_subprocess):
    wrap = PodmanWrapper(app_name="pytest", scan_name="pytest", image="nothing")

    version = '{"Client":{"APIVersion":"5.2.2","Version":"5.2.2","GoVersion":"go1.22.6","GitCommit":"","BuiltTime":"Wed Aug 21 02:00:00 2024","Built":1724198400,"OsArch":"linux/amd64","Os":"linux"}}'
    run = subprocess.CompletedProcess(args=None, returncode=0, stdout=version.encode('utf-8'))

    mock_subprocess.return_value = run

    wrap.change_user_id(1000, 1000)

    i = wrap.opts.index("--userns")
    assert wrap.opts[i + 1] == "keep-id:uid=1000,gid=1000"

@patch("scanners.podman_wrapper.subprocess.run")
def test_change_user_id_workaround(mock_subprocess):
    wrap = PodmanWrapper(app_name="pytest", scan_name="pytest", image="nothing")

    info = """
{
  "host": {
    "idMappings": {
      "gidmap": [
        {
          "container_id": 0,
          "host_id": 1000,
          "size": 1
        },
        {
          "container_id": 1,
          "host_id": 524288,
          "size": 65536
        }
      ],
      "uidmap": [
        {
          "container_id": 0,
          "host_id": 1000,
          "size": 1
        },
        {
          "container_id": 1,
          "host_id": 524288,
          "size": 65536
        }
      ]
    }
  }
}
"""

	
    run = subprocess.CompletedProcess(args=None, returncode=0, stdout=info.encode('utf-8'))

    mock_subprocess.return_value = run

    wrap.change_user_id_workaround(1000, 1000)

    assert "--uidmap" in wrap.opts
    assert "0:1:1000" in wrap.opts
    assert "--gidmap" in wrap.opts
