import os

from conftest import tee_log  # pylint: disable=E0611
from conftest import TestBase  # pylint: disable=E0611
from conftest import wait_until_ready  # pylint: disable=E0611


class TestNessus(TestBase):
    def test_nessus(self):
        """Test rapidast find expected number of findings in VAPI"""
        self.create_from_yaml(f"{self.tempdir}/nessus-deployment.yaml")
        self.create_from_yaml(f"{self.tempdir}/nessus-service.yaml")
        wait_until_ready(label_selector="app=nessus", timeout=300)  # nessus is slow to pull and start

        self.create_from_yaml(f"{self.tempdir}/rapidast-nessus-configmap.yaml")
        self.create_from_yaml(f"{self.tempdir}/rapidast-nessus-pod.yaml")
        wait_until_ready(field_selector="metadata.name=rapidast-nessus")

        logfile = os.path.join(self.tempdir, "rapidast-nessus.log")
        tee_log("rapidast-nessus", logfile)
