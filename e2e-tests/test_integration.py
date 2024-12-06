import json
import os
import re

from conftest import tee_log  # pylint: disable=E0611
from conftest import TestBase  # pylint: disable=E0611
from conftest import wait_until_ready  # pylint: disable=E0611


class TestRapiDAST(TestBase):
    def test_vapi(self):
        """Test rapidast find expected number of findings in VAPI"""
        self.create_from_yaml(f"{self.tempdir}/vapi-deployment.yaml")
        self.create_from_yaml(f"{self.tempdir}/vapi-service.yaml")
        wait_until_ready(label_selector="app=vapi")

        self.create_from_yaml(f"{self.tempdir}/rapidast-vapi-configmap.yaml")
        self.create_from_yaml(f"{self.tempdir}/rapidast-vapi-pod.yaml")
        wait_until_ready(field_selector="metadata.name=rapidast-vapi")

        logfile = os.path.join(self.tempdir, "rapidast-vapi.log")
        tee_log("rapidast-vapi", logfile)

        # XXX relies on rapidast-vapi pod cat-ing the result json file after execution
        with open(logfile, "r", encoding="utf-8") as f:
            logs = f.read()
            pattern = r"^{\s*$.*$"
            matches = re.findall(pattern, logs, re.MULTILINE | re.DOTALL)
            assert matches, f"{logfile} did not contain expected json results"
            results = json.loads(matches[0])

        assert len(results["site"][0]["alerts"]) == 3

    def test_trivy(self):
        self.create_from_yaml(f"{self.tempdir}/rapidast-trivy-configmap.yaml")
        self.create_from_yaml(f"{self.tempdir}/rapidast-trivy-pod.yaml")
        wait_until_ready(field_selector="metadata.name=rapidast-trivy")

        logfile = os.path.join(self.tempdir, "rapidast-trivy.log")
        tee_log("rapidast-trivy", logfile)

        expected_line = "INFO:scanner: 'generic_trivy' completed successfully"
        with open(logfile, "r", encoding="utf-8") as f:
            logs = f.read()
            assert expected_line in logs, f"{logfile} does not contain expected line: {expected_line}"

    def test_oobtkube(self):
        self.create_from_yaml(f"{self.tempdir}/task-controller-deployment.yaml")

        self.create_from_yaml(f"{self.tempdir}/rapidast-oobtkube-configmap.yaml")
        self.create_from_yaml(f"{self.tempdir}/rapidast-oobtkube-service.yaml")
        self.create_from_yaml(f"{self.tempdir}/rapidast-oobtkube-pod.yaml")
        wait_until_ready(field_selector="metadata.name=rapidast-oobtkube")

        logfile = os.path.join(self.tempdir, "rapidast-oobtkube.log")
        tee_log("rapidast-oobtkube", logfile)

        expected_line = "RESULT: OOB REQUEST DETECTED"
        with open(logfile, "r", encoding="utf-8") as f:
            logs = f.read()
            assert expected_line in logs, f"{logfile} does not contain expected line: {expected_line}"
