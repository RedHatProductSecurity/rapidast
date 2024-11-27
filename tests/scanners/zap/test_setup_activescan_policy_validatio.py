from pathlib import Path

import pytest

from scanners.zap.zap import InvalidXMLFileError
from scanners.zap.zap import MismatchedPolicyNameError
from scanners.zap.zap import MissingConfigurationNodeError
from scanners.zap.zap import MissingPolicyNodeError
from scanners.zap.zap import PolicyFileNotFoundError
from scanners.zap.zap import validate_active_scan_policy


@pytest.fixture
def valid_policy_file(tmp_path):
    policy_name = "policy1"
    valid_xml_content = """<configuration>
                             <policy>policy1</policy>
                             <setting name="max_connections">100</setting>
                           </configuration>"""
    file_path = tmp_path / f"{policy_name}.policy"
    file_path.write_text(valid_xml_content)
    return file_path


@pytest.fixture
def invalid_xml_file(tmp_path):
    policy_name = "policy1"
    invalid_xml_content = """<configuration>
                              <policy>policy2</policy>
                            </configuration>"""  # Mismatched policy name
    file_path = tmp_path / f"{policy_name}.policy"
    file_path.write_text(invalid_xml_content)
    return file_path


@pytest.fixture
def missing_policy_file():
    return Path("/non/existent/path/policy1.policy")


def test_valid_policy(valid_policy_file):
    validate_active_scan_policy(valid_policy_file)


def test_missing_policy_file(missing_policy_file):
    with pytest.raises(PolicyFileNotFoundError):
        validate_active_scan_policy(missing_policy_file)


def test_invalid_xml_file(invalid_xml_file):
    with pytest.raises(MismatchedPolicyNameError):
        validate_active_scan_policy(invalid_xml_file)


def test_invalid_xml_parse(invalid_xml_file):
    invalid_xml_content = """<configuration>
                               <policy>policy1</policy>
                             </configuration"""  # Missing closing tag
    file_path = invalid_xml_file
    file_path.write_text(invalid_xml_content)

    with pytest.raises(InvalidXMLFileError):
        validate_active_scan_policy(file_path)


def test_missing_configuration_node(invalid_xml_file):
    invalid_xml_content = """<as>
                               <policy>policy1</policy>
                             </as>"""
    file_path = invalid_xml_file
    file_path.write_text(invalid_xml_content)

    with pytest.raises(MissingConfigurationNodeError):
        validate_active_scan_policy(file_path)


def test_missing_policy_node(invalid_xml_file):
    invalid_xml_content = """<configuration>
                               <po>policy1</po>
                             </configuration>"""
    file_path = invalid_xml_file
    file_path.write_text(invalid_xml_content)

    with pytest.raises(MissingPolicyNodeError):
        validate_active_scan_policy(file_path)
