import base64
import logging
from typing import Dict

import pytest
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

    @pytest.mark.parametrize(
        "auth_type,expected_log,header_name,header_value_func",
        [
            (
                "http-basic",
                "ZAP configured with HTTP Basic Authentication",
                "Authorization",
                lambda: f"Basic {base64.b64encode(b'user:mypassw0rd').decode('utf-8')}",
            ),
            (
                "http-header",
                "ZAP configured with Authentication using HTTP Header",
                "Authorization",
                lambda: "MySecretHeader",
            ),
            ("cookie", "ZAP configured with Cookie authentication", "Cookie", lambda: "session_id=abc123testcookie"),
        ],
    )
    def test_authentication(self, auth_type, expected_log, header_name, header_value_func):
        """Test rapidast with various authentication methods configured"""

        self.create_from_yaml(f"{self.tempdir}/rapidast-vapi-configmap-{auth_type}.yaml")
        self.create_from_yaml(f"{self.tempdir}/rapidast-vapi-pod-{auth_type}.yaml")

        assert is_pod_with_field_selector_successfully_completed(
            field_selector=f"metadata.name=rapidast-vapi-{auth_type}", timeout=360
        )

        logs = get_log_from_pod(self.tempdir, f"rapidast-vapi-{auth_type}", container="rapidast", log_format="text")
        data = get_log_from_pod(
            self.tempdir,
            f"rapidast-vapi-{auth_type}",
            filename_suffix="results",
            container="results",
            log_format="json",
        )

        assert expected_log in logs, f"ZAP logs should indicate {auth_type} authentication was configured"

        # Verify authentication header is present in scan results
        # NOTE: All authentication values are dummy test credentials - not real secrets
        expected_header_value = header_value_func()
        auth_header_found = verify_specific_auth_header_value(data, header_name, expected_header_value)
        assert (
            auth_header_found
        ), f"{header_name} header with value '{expected_header_value}' should be found in scan results"


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
