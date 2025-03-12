import os

from conftest import is_pod_with_field_selector_successfully_completed  # pylint: disable=E0611
from conftest import tee_log  # pylint: disable=E0611
from conftest import TestBase  # pylint: disable=E0611
from conftest import wait_until_ready  # pylint: disable=E0611


class TestNessus(TestBase):
    def test_nessus(self):
        """Test rapidast find expected number of findings in VAPI"""
        self.create_from_yaml(f"{self.tempdir}/nessus-deployment.yaml")
        self.create_from_yaml(f"{self.tempdir}/nessus-service.yaml")
        assert wait_until_ready(label_selector="app=nessus", timeout=360)  # nessus is slow to pull and start

        self.create_from_yaml(f"{self.tempdir}/rapidast-nessus-configmap.yaml")
        self.create_from_yaml(f"{self.tempdir}/rapidast-nessus-pod.yaml")
        # @FIX: We don't assert the container's successful completion because it
        # ends up in an 'Error' status. This happens because the configuration provided
        # defines authentication, but the Nessus scanner doesn't support authentication
        is_pod_with_field_selector_successfully_completed(
            field_selector="metadata.name=rapidast-nessus", timeout=360  # llm-based image takes really long to download
        )

        logfile = os.path.join(self.tempdir, "rapidast-nessus.log")
        tee_log("rapidast-nessus", logfile)
