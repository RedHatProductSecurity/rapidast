import json
import os
import re

from conftest import is_pod_with_field_selector_successfully_completed  # pylint: disable=E0611
from conftest import tee_log  # pylint: disable=E0611
from conftest import TestBase  # pylint: disable=E0611
from conftest import wait_until_ready  # pylint: disable=E0611


class TestRapiDAST(TestBase):
    def test_vapi(self):
        """Test rapidast find expected number of findings in VAPI"""
        self.create_from_yaml(f"{self.tempdir}/vapi-deployment.yaml")
        self.create_from_yaml(f"{self.tempdir}/vapi-service.yaml")
        assert wait_until_ready(label_selector="app=vapi")

        self.create_from_yaml(f"{self.tempdir}/rapidast-vapi-configmap.yaml")
        self.create_from_yaml(f"{self.tempdir}/rapidast-vapi-pod.yaml")
        assert is_pod_with_field_selector_successfully_completed(
            field_selector="metadata.name=rapidast-vapi", timeout=360  # llm-based image takes really long to download
        )

        # two containers run in this pod, one for running rapidast and one for printing json results
        logfile = os.path.join(self.tempdir, "rapidast-vapi.log")
        results = os.path.join(self.tempdir, "rapidast-vapi-results.json")
        tee_log("rapidast-vapi", logfile, container="rapidast")
        tee_log("rapidast-vapi", results, container="results")

        with open(results, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert len(data["site"][0]["alerts"]) == 3

        with open(logfile, "r", encoding="utf-8") as f:
            logs = f.read()

        # Verify that the spiderAjax job is functioning correctly
        # @TODO: Consider implementing this using ZAP's built-in monitor test framework
        #        https://www.zaproxy.org/docs/desktop/addons/automation-framework/test-monitor/
        #        This will require refining how parameters are passed within the automation framework
        match = re.search(r"Job spiderAjax found (\d+) URLs", logs)
        assert match is not None, f"{logfile} does not contain a line matching 'Job spiderAjax found X URLs'"
        url_count = int(match.group(1))
        assert url_count > 1, f"{logfile} indicates only {url_count} URL(s) found, expected more than 1"

    def test_trivy(self):
        self.create_from_yaml(f"{self.tempdir}/rapidast-trivy-configmap.yaml")
        self.create_from_yaml(f"{self.tempdir}/rapidast-trivy-pod.yaml")
        assert is_pod_with_field_selector_successfully_completed(
            field_selector="metadata.name=rapidast-trivy", timeout=360  # llm-based image takes really long to download
        )

        logfile = os.path.join(self.tempdir, "rapidast-trivy.log")
        tee_log("rapidast-trivy", logfile)

        expected_line = "INFO:scanner: 'generic_trivy' completed successfully"
        with open(logfile, "r", encoding="utf-8") as f:
            logs = f.read()
            assert expected_line in logs, f"{logfile} does not contain expected line: {expected_line}"

    def test_oobtkube(self, _setup_teardown_for_oobkube):
        self.create_from_yaml(f"{self.tempdir}/cm-controller-deployment.yaml")

        self.create_from_yaml(f"{self.tempdir}/rapidast-oobtkube-configmap.yaml")
        self.create_from_yaml(f"{self.tempdir}/rapidast-oobtkube-service.yaml")
        self.create_from_yaml(f"{self.tempdir}/rapidast-oobtkube-pod.yaml")
        assert is_pod_with_field_selector_successfully_completed(
            field_selector="metadata.name=rapidast-oobtkube",
            timeout=360,  # llm-based image takes really long to download
        )

        logfile = os.path.join(self.tempdir, "rapidast-oobtkube.log")
        tee_log("rapidast-oobtkube", logfile)

        expected_line = "RESULT: OOB REQUEST DETECTED"
        with open(logfile, "r", encoding="utf-8") as f:
            logs = f.read()
            assert expected_line in logs, f"{logfile} does not contain expected line: {expected_line}"
