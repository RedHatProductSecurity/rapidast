import copy
import json
import os
import tempfile
from unittest.mock import mock_open

import pytest

from configmodel.models.exclusions import Exclusions
from configmodel.models.exclusions import Rule
from rapidast import filter_sarif_report


@pytest.fixture
def sample_sarif_data_single_run():
    """A sample SARIF data structure for testing with a single run"""
    return {
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "TestScanner"}},
                "results": [
                    {
                        "ruleId": "CWE-79",
                        "level": "error",
                        "message": {"text": "Kept finding"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "https://www.example.com/app/index.html"}
                                }
                            }
                        ],
                    },
                    {
                        "ruleId": "DAST-1234-KnownFP",
                        "level": "warning",
                        "message": {"text": "False positive finding"},
                        "locations": [
                            {"physicalLocation": {"artifactLocation": {"uri": "https://www.example.com/app/test.php"}}}
                        ],
                    },
                ],
            }
        ],
    }


@pytest.fixture
def config_to_filter_fp_rule_id():
    """Exclusions config to filter DAST-1234-KnownFP"""
    return Exclusions(
        enabled=True,
        rules=[Rule(name="Exclude known FP ruleId", cel_expression='result.ruleId == "DAST-1234-KnownFP"')],
    )


@pytest.fixture
def config_no_rules():
    """Exclusions config with no rules"""
    return Exclusions(enabled=True, rules=[])


@pytest.fixture
def exclusion_config_disabled():
    """Exclusions config with filtering disabled"""
    return Exclusions(enabled=False, rules=[Rule(name="Some rule", cel_expression="true")])


class TestFilterSarifReport:
    def test_filter_sarif_report_success(
        self,
        sample_sarif_data_single_run,
        config_to_filter_fp_rule_id,
    ):
        """
        Tests successful filtering and saving of a SARIF report
        """

        with tempfile.NamedTemporaryFile(mode="w+", delete=False, suffix=".sarif", encoding="utf-8") as temp_input_file:
            json.dump(sample_sarif_data_single_run, temp_input_file)
            temp_input_file_path = temp_input_file.name

        with tempfile.NamedTemporaryFile(
            mode="w+", delete=False, suffix=".sarif", encoding="utf-8"
        ) as temp_output_file:
            temp_output_file_path = temp_output_file.name

        try:
            filter_sarif_report(
                input_report_path=temp_input_file_path,
                output_report_path=temp_output_file_path,
                exclusions_config=config_to_filter_fp_rule_id,
            )

            with open(temp_output_file_path, "r", encoding="utf-8") as f:
                written_content = f.read()
            loaded_written_content = json.loads(written_content)

            expected_filtered_data = copy.deepcopy(sample_sarif_data_single_run)
            expected_filtered_data["runs"][0]["results"] = [sample_sarif_data_single_run["runs"][0]["results"][0]]

            assert loaded_written_content == expected_filtered_data

        finally:
            if os.path.exists(temp_input_file_path):
                os.remove(temp_input_file_path)
            if os.path.exists(temp_output_file_path):
                os.remove(temp_output_file_path)

    def test_filter_sarif_report_input_file_not_found(
        self,
        mocker,
        config_to_filter_fp_rule_id,
    ):
        """
        Tests that FileNotFoundError is raised if the input file does not exist.
        """

        mock_input_path = "non_existent_input.sarif"
        mock_output_path = "output.sarif"

        mocker.patch("os.path.exists", return_value=False)

        with pytest.raises(FileNotFoundError):
            filter_sarif_report(
                input_report_path=mock_input_path,
                output_report_path=mock_output_path,
                exclusions_config=config_to_filter_fp_rule_id,
            )

    def test_filter_sarif_report_invalid_json(
        self,
        mocker,
        config_to_filter_fp_rule_id,
    ):
        """
        Tests that JSONDecodeError is raised if the input file is not valid JSON
        """

        mock_input_path = "invalid.sarif"
        mock_output_path = "output.sarif"
        invalid_json_content = "{This is not valid json"

        mocker.patch("os.path.exists", return_value=True)

        mocker.patch("builtins.open", mock_open(read_data=invalid_json_content))

        with pytest.raises(json.JSONDecodeError):
            filter_sarif_report(
                input_report_path=mock_input_path,
                output_report_path=mock_output_path,
                exclusions_config=config_to_filter_fp_rule_id,
            )

    def test_filter_sarif_report_output_io_error(
        self,
        mocker,
        sample_sarif_data_single_run,
        config_to_filter_fp_rule_id,
    ):
        """
        Tests that IOError is raised if there's an error writing the output file
        """

        mock_input_path = "input.sarif"
        mock_output_path = "/nonexistent/path/to/output.sarif"

        mocker.patch("os.path.exists", return_value=True)

        mock_read_file = mock_open(read_data=json.dumps(sample_sarif_data_single_run))

        def mock_open_side_effect(file, mode, **kwargs):
            if mode == "r":
                return mock_read_file.return_value
            elif mode == "w":
                raise IOError("Permission denied")
            raise ValueError(f"Unexpected mode: {mode}")

        mocker.patch("builtins.open", side_effect=mock_open_side_effect)

        with pytest.raises(IOError):
            filter_sarif_report(
                input_report_path=mock_input_path,
                output_report_path=mock_output_path,
                exclusions_config=config_to_filter_fp_rule_id,
            )

    def test_filter_sarif_report_filtering_disabled(
        self,
        mocker,
        sample_sarif_data_single_run,
        exclusion_config_disabled,
    ):
        """
        Tests that filtering is skipped if the config has filtering disabled.
        The output file should be identical to the input.
        """
        mock_input_path = "input.sarif"
        mock_output_path = "output_disabled.sarif"

        mocker.patch("os.path.exists", return_value=True)
        mock_read_file = mock_open(read_data=json.dumps(sample_sarif_data_single_run))
        mock_write_file = mock_open()

        def mock_open_side_effect(file, mode, **kwargs):
            if mode == "r":
                return mock_read_file.return_value
            elif mode == "w":
                return mock_write_file.return_value
            raise ValueError(f"Unexpected mode: {mode}")

        mocker.patch("builtins.open", side_effect=mock_open_side_effect)

        filter_sarif_report(
            input_report_path=mock_input_path,
            output_report_path=mock_output_path,
            exclusions_config=exclusion_config_disabled,
        )

        written_content = "".join([call.args[0] for call in mock_write_file.return_value.write.call_args_list])
        loaded_written_content = json.loads(written_content)
        assert loaded_written_content == sample_sarif_data_single_run

    def test_filter_sarif_report_no_rules(
        self,
        mocker,
        sample_sarif_data_single_run,
        config_no_rules,
    ):
        """
        Tests that filtering is skipped if the config has no rules.
        The output file should be identical to the input.
        """

        mock_input_path = "input.sarif"
        mock_output_path = "output_no_rules.sarif"

        mocker.patch("os.path.exists", return_value=True)
        mock_read_file = mock_open(read_data=json.dumps(sample_sarif_data_single_run))
        mock_write_file = mock_open()

        def mock_open_side_effect(file, mode, **kwargs):
            if mode == "r":
                return mock_read_file.return_value
            elif mode == "w":
                return mock_write_file.return_value
            raise ValueError(f"Unexpected mode: {mode}")

        mocker.patch("builtins.open", side_effect=mock_open_side_effect)

        filter_sarif_report(
            input_report_path=mock_input_path, output_report_path=mock_output_path, exclusions_config=config_no_rules
        )

        written_content = "".join([call.args[0] for call in mock_write_file.return_value.write.call_args_list])
        loaded_written_content = json.loads(written_content)
        assert loaded_written_content == sample_sarif_data_single_run
