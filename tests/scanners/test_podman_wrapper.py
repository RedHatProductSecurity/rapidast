import shutil

import pytest

from scanners.podman_wrapper import PodmanWrapper


@pytest.mark.skipif(
    shutil.which("podman") == False, reason="podman is required for this test"
)
def test_podman_mappings():
    wrap = PodmanWrapper(app_name="pytest", scan_name="pytest", image="nothing")

    wrap.change_user_id(1000, 1000)

    assert "--uidmap" in wrap.opts
    assert "0:1:1000" in wrap.opts
    assert "--gidmap" in wrap.opts
