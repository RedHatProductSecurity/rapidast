import base64
import logging
from typing import Dict

from test_integration import get_log_from_pod  # pylint: disable=E0611

from conftest import is_pod_with_field_selector_successfully_completed  # pylint: disable=E0611
from conftest import TestBase  # pylint: disable=E0611
from conftest import wait_until_ready  # pylint: disable=E0611


class TestRapiDASTAuthentication(TestBase):
    @classmethod
    def setup_class(cls):
        """Set up shared VAPI instance for all authentication tests"""
        super().setup_class()
        cls.create_from_yaml(cls, f"{cls.tempdir}/vapi-auth-deployment.yaml")
        cls.create_from_yaml(cls, f"{cls.tempdir}/vapi-auth-service.yaml")
        assert wait_until_ready(label_selector="app=vapi-auth")

    def test_http_basic_authentication(self):
        """Test rapidast with HTTP Basic authentication configured"""

        self.create_from_yaml(f"{self.tempdir}/rapidast-vapi-configmap-http-basic.yaml")
        self.create_from_yaml(f"{self.tempdir}/rapidast-vapi-pod-http-basic.yaml")
        assert is_pod_with_field_selector_successfully_completed(
            field_selector="metadata.name=rapidast-vapi-http-basic", timeout=360
        )

        logs = get_log_from_pod(self.tempdir, "rapidast-vapi-http-basic", container="rapidast", log_format="text")
        data = get_log_from_pod(
            self.tempdir,
            "rapidast-vapi-http-basic",
            filename_suffix="results",
            container="results",
            log_format="json",
        )

        # Verify that HTTP Basic authentication was configured correctly in logs
        assert (
            "ZAP configured with HTTP Basic Authentication" in logs
        ), "ZAP logs should indicate HTTP Basic authentication was configured"

        # Verify that the Authorization Basic header with correct credentials is present
        # NOTE: "user:mypassw0rd" are dummy test credentials for e2e testing - not real secrets
        expected_credentials = base64.b64encode(b"user:mypassw0rd").decode("utf-8")
        basic_auth_header_found = verify_specific_auth_header_value(
            data, "Authorization", f"Basic {expected_credentials}"
        )
        assert (
            basic_auth_header_found
        ), "Authorization header with correct Basic credentials should be found in scan results"

    def test_http_header_authentication(self):
        """Test rapidast with HTTP Header authentication configured"""

        self.create_from_yaml(f"{self.tempdir}/rapidast-vapi-configmap-http-header.yaml")
        self.create_from_yaml(f"{self.tempdir}/rapidast-vapi-pod-http-header.yaml")
        assert is_pod_with_field_selector_successfully_completed(
            field_selector="metadata.name=rapidast-vapi-http-header", timeout=360
        )

        logs = get_log_from_pod(self.tempdir, "rapidast-vapi-http-header", container="rapidast", log_format="text")
        data = get_log_from_pod(
            self.tempdir,
            "rapidast-vapi-http-header",
            filename_suffix="results",
            container="results",
            log_format="json",
        )

        assert (
            "ZAP configured with Authentication using HTTP Header" in logs
        ), "ZAP logs should indicate HTTP Header authentication was configured"

        # NOTE: "MySecretHeader" is a dummy test header value for e2e testing - not a real secret
        custom_header_found = verify_specific_auth_header_value(data, "Authorization", "MySecretHeader")
        assert (
            custom_header_found
        ), "Authorization header with exact custom value 'MySecretHeader' should be found in scan results"


def verify_specific_auth_header_value(report_data: Dict, header_name: str, expected_header_value: str) -> bool:
    """
    Verifies that a specific authentication header with exact value is present in the ZAP report.

    Args:
        report_data: The ZAP JSON report data
        header_name: The name of the header to look for (e.g., "Authorization")
        expected_header_value: The exact header value to look for

    Returns:
        bool: True if the exact authentication header value is found, False otherwise
    """
    if not report_data:
        logging.warning("No report data provided")
        return False

    report_str = str(report_data).lower()
    header_name_lower = header_name.lower()
    expected_value_lower = expected_header_value.lower()

    header = f"{header_name_lower}: {expected_value_lower}"
    return header in report_str
