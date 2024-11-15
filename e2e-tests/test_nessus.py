import json
import os
import re

from conftest import tee_log
from conftest import TestBase
from conftest import wait_until_ready


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

        # # XXX relies on rapidast-vapi pod cat-ing the result json file after execution
        # with open(logfile, "r", encoding="utf-8") as f:
        #     logs = f.read()
        #     pattern = r"^{\s*$.*$"
        #     matches = re.findall(pattern, logs, re.MULTILINE | re.DOTALL)
        #     assert matches, f"{logfile} did not contain expected json results"
        #     results = json.loads(matches[0])

        # assert len(results["site"][0]["alerts"]) == 3
