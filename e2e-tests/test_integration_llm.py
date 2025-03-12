import os

from conftest import tee_log  # pylint: disable=E0611
from conftest import TestBase  # pylint: disable=E0611
from conftest import wait_until_ready  # pylint: disable=E0611


class TestLLM(TestBase):
    def test_llm(self):
        self.create_from_yaml(f"{self.tempdir}/tchat-deployment.yaml")
        self.create_from_yaml(f"{self.tempdir}/tchat-service.yaml")
        wait_until_ready(label_selector="app=tchat", timeout=300)  # llm is slow to pull and start

        self.create_from_yaml(f"{self.tempdir}/rapidast-llm-configmap.yaml")
        self.create_from_yaml(f"{self.tempdir}/rapidast-llm-pod.yaml")
        wait_until_ready(field_selector="metadata.name=rapidast-llm")

        logfile = os.path.join(self.tempdir, "rapidast-llm.log")
        tee_log("rapidast-llm", logfile)
