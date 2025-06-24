import json
import os
import re
from typing import Optional
from typing import Union

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
        logs = get_log_from_pod(self.tempdir, "rapidast-vapi", container="rapidast", log_format="text")
        data = get_log_from_pod(
            self.tempdir, "rapidast-vapi", filename_suffix="results", container="results", log_format="json"
        )

        assert len(data["site"][0]["alerts"]) == 3

        # Verify that URLs listed for exclusion in subsequent tests are present in the report.
        # This list should be kept in sync with the configuration scanners.zap.urls.excludes in
        # manifests/rapidast-vapi-configmap-urls-exclusions.yaml
        excluded_urls = ["http://vapi:5000/api/pets/id/.*", "http://vapi:3000/_next/static/css/.*.css"]
        passive_scan_alertrefs = ["10021", "10036"]

        excluded = verify_zap_report_urls(data, excluded_urls)

        assert all(info["found"] for info in excluded.values())

        # Verify that the spiderAjax job is functioning correctly
        # @TODO: Consider implementing this using ZAP's built-in monitor test framework
        #        https://www.zaproxy.org/docs/desktop/addons/automation-framework/test-monitor/
        #        This will require refining how parameters are passed within the automation framework
        match = re.search(r"Job spiderAjax found (\d+) URLs", logs)
        assert match is not None, "Zap's logs do not contain a line matching 'Job spiderAjax found X URLs'"
        url_count = int(match.group(1))
        assert url_count > 1, f"Zap's logs indicate only {url_count} URL(s) found, expected more than 1"

        # Check that the correct ZAP active scan policy was applied
        match = "Job activeScan set policy = API-scan-minimal" in logs
        assert match, "Zap's logs do not contain a line matching 'Job activeScan set policy = API-scan-minimal'"
        # Verify expected ZAP alert references from the scan policy are included in the report
        alert_refs_to_check = ["40018"]
        results = check_zap_alert_refs(data, alert_refs_to_check)
        assert not results["not_found"], f"Missing expected alert references from scan policy: {results['not_found']}"

        # Verify expected ZAP alert references from the passive scan are included in the report
        results = check_zap_alert_refs(data, passive_scan_alertrefs)
        assert not results["not_found"], f"Missing expected alert references from passive scan: {results['not_found']}"

        # Verify that the form handler correctly submitted and logged expected URLs
        expected_form_urls = ["http://vapi:5000/api/pets/name/pet_aaaa"]
        form_url_check = verify_zap_report_urls(data, expected_form_urls)
        assert all(
            result["found"] for result in form_url_check.values()
        ), "One or more expected form submission URLs were not found in the ZAP report"

        # Verify that ZAP report does not contain alerts for URLs excluded in the scan configuration
        self.replace_from_yaml(f"{self.tempdir}/rapidast-vapi-configmap-urls-exclusions.yaml")
        self.replace_from_yaml(f"{self.tempdir}/rapidast-vapi-pod.yaml")
        assert is_pod_with_field_selector_successfully_completed(
            field_selector="metadata.name=rapidast-vapi", timeout=360  # llm-based image takes really long to download
        )

        data = get_log_from_pod(
            self.tempdir,
            "rapidast-vapi",
            filename_suffix="excluded-urls-results",
            container="results",
            log_format="json",
        )

        excluded = verify_zap_report_urls(data, excluded_urls)

        assert all(not info["found"] for info in excluded.values())

        # Ensure passiveScan can be successfully disabled
        self.replace_from_yaml(f"{self.tempdir}/rapidast-vapi-configmap-no-passivescan.yaml")
        self.replace_from_yaml(f"{self.tempdir}/rapidast-vapi-pod.yaml")
        assert is_pod_with_field_selector_successfully_completed(
            field_selector="metadata.name=rapidast-vapi", timeout=360  # llm-based image takes really long to download
        )

        data = get_log_from_pod(
            self.tempdir, "rapidast-vapi", filename_suffix="no-passivescan", container="results", log_format="json"
        )

        results = check_zap_alert_refs(data, passive_scan_alertrefs)
        assert not results["found"], f"Unexpected passive scan alert references found: {results['found']}"

    def test_trivy(self):
        self.create_from_yaml(f"{self.tempdir}/rapidast-trivy-configmap.yaml")
        self.create_from_yaml(f"{self.tempdir}/rapidast-trivy-pod.yaml")
        assert is_pod_with_field_selector_successfully_completed(
            field_selector="metadata.name=rapidast-trivy", timeout=360  # llm-based image takes really long to download
        )

        expected_line = "INFO:scanner: 'generic_trivy' completed successfully"
        logs = get_log_from_pod(self.tempdir, "rapidast-trivy", log_format="text")
        assert expected_line in logs, f"Trivy's logs do not contain expected line: {expected_line}"

    def test_oobtkube(self, _setup_teardown_for_oobkube):
        self.create_from_yaml(f"{self.tempdir}/cm-controller-deployment.yaml")

        self.create_from_yaml(f"{self.tempdir}/rapidast-oobtkube-configmap.yaml")
        self.create_from_yaml(f"{self.tempdir}/rapidast-oobtkube-service.yaml")
        self.create_from_yaml(f"{self.tempdir}/rapidast-oobtkube-pod.yaml")
        assert is_pod_with_field_selector_successfully_completed(
            field_selector="metadata.name=rapidast-oobtkube",
            timeout=360,  # llm-based image takes really long to download
        )

        expected_line = "RESULT: OOB REQUEST DETECTED"
        logs = get_log_from_pod(self.tempdir, "rapidast-oobtkube", log_format="text")
        assert expected_line in logs, f"OOBKube's logs do not contain expected line: {expected_line}"


def verify_zap_report_urls(report_data: dict, urls: list[str]) -> dict:
    """
    Checks if any alert instance URIs from a ZAP report contain any of the specified
    URL patterns
    """

    def _get_all_instance_uris(report_data: dict) -> list[str]:
        """
        Helper function to extract all unique URIs from alert instances in the ZAP report
        """
        uris = set()
        if "site" not in report_data or not isinstance(report_data.get("site"), list):
            assert False, "'site' key not found in the ZAP report. No alerts to check"

        for site in report_data["site"]:  # pylint: disable=R1702 too-many-nested-blocks
            if "alerts" in site and isinstance(site.get("alerts"), list):
                for alert in site["alerts"]:
                    if "instances" in alert and isinstance(alert.get("instances"), list):
                        for instance in alert["instances"]:
                            if "uri" in instance:
                                uris.add(instance["uri"])
        return list(uris)

    compiled_patterns = [(re.compile(pattern), pattern) for pattern in urls]
    results = {pattern: {"found": False} for pattern in urls}

    all_report_uris = _get_all_instance_uris(report_data)

    for uri in all_report_uris:
        for compiled_regex, original_pattern_str in compiled_patterns:
            if compiled_regex.search(uri):
                results[original_pattern_str]["found"] = True
    return results


def check_zap_alert_refs(report_data: dict, target_alert_refs: list[str]) -> dict:
    """
    Checks if a list of specific ZAP alert IDs (pluginid) are present in a ZAP report

    Returns:
        A dictionary indicating which alertRefs were found and which were not.
        Example: {'found': ['10020'], 'not_found': ['90001']}
    """

    if "site" not in report_data or not isinstance(report_data["site"], list):
        return {"found": [], "not_found": target_alert_refs}

    found_alert_refs = set()  # Use a set for efficient lookups and to avoid duplicates

    for site in report_data["site"]:
        if "alerts" not in site or not isinstance(site["alerts"], list):
            continue

        for alert in site["alerts"]:
            plugin_id = alert.get("pluginid")
            if plugin_id and plugin_id in target_alert_refs:
                found_alert_refs.add(plugin_id)

    not_found_alert_refs = [ref for ref in target_alert_refs if ref not in found_alert_refs]

    return {"found": sorted(list(found_alert_refs)), "not_found": sorted(not_found_alert_refs)}


def get_log_from_pod(
    tempdir: str,
    pod_name: str,
    filename_suffix: Optional[str] = None,
    container: Optional[str] = None,
    log_format: str = "text",
) -> Union[str, dict]:
    """
    Fetches and returns a log file from a specific container in a pod

    Args:
        tempdir: Directory to store the log file
        pod_name: Name of the pod (e.g., 'rapidast-vapi')
        filename_suffix: Filename suffix, e.g. 'results' or 'log'
        container: Name of the container in the pod
        log_format: Format of the log ('json' or 'text')

    Returns:
        dict | str: Parsed JSON if log_format='json', raw string if 'text'

    Raises:
        ValueError: If `log_format` is unsupported or JSON parsing fails
    """
    extension = "json" if log_format == "json" else "log"
    filename = f"{pod_name}.{extension}" if not filename_suffix else f"{pod_name}-{filename_suffix}.{extension}"
    path = os.path.join(tempdir, filename)
    tee_log(pod_name, path, container=container)

    with open(path, "r", encoding="utf-8") as f:
        content = f.read()

    if log_format == "json":
        try:
            return json.loads(content)
        except json.JSONDecodeError as e:
            raise ValueError(f"Failed to parse JSON log from {path}: {e}") from e
    elif log_format == "text":
        return content
    else:
        raise ValueError(f"Unsupported log format: {log_format}")
