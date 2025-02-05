import unittest
from unittest.mock import patch

from rapidast import validate_config_schema


class TestValidateConfigSchema(unittest.TestCase):
    @patch("rapidast.load_config_file")
    @patch("yaml.safe_load")
    @patch("pathlib.Path.exists")
    def test_missing_config_version(self, mock_exists, mock_safe_load, mock_load_config):
        mock_load_config.return_value = "mocked_config_file_content"
        mock_safe_load.return_value = {"config": {}}

        config_file = "config_file.yaml"

        result = validate_config_schema(config_file)
        self.assertFalse(result)

    @patch("rapidast.load_config_file")
    @patch("yaml.safe_load")
    @patch("pathlib.Path.exists")
    def test_schema_file_missing(self, mock_exists, mock_safe_load, mock_load_config):
        mock_load_config.return_value = "mocked_config_file_content"
        mock_safe_load.return_value = {"config": {"configVersion": "1.0"}}
        mock_exists.return_value = False

        config_file = "config_file.yaml"

        result = validate_config_schema(config_file)
        self.assertFalse(result)

    @patch("rapidast.load_config_file")
    @patch("yaml.safe_load")
    @patch("pathlib.Path.exists")
    @patch("rapidast.deep_traverse_and_replace")
    @patch("rapidast.validate_config")
    def test_failed_validation(self, mock_validate, mock_deep_traverse, mock_exists, mock_safe_load, mock_load_config):
        mock_load_config.return_value = "mocked_config_file_content"
        mock_safe_load.return_value = {"config": {"configVersion": "1.0"}}
        mock_exists.return_value = True
        mock_deep_traverse.return_value = {"mocked": "resolved_config"}
        mock_validate.return_value = False

        config_file = "config_file.yaml"

        result = validate_config_schema(config_file)

        self.assertFalse(result)

    @patch("rapidast.load_config_file")
    @patch("yaml.safe_load")
    @patch("pathlib.Path.exists")
    @patch("rapidast.deep_traverse_and_replace")
    @patch("rapidast.validate_config")
    def test_valid_config_with_schema(
        self, mock_validate, mock_deep_traverse, mock_exists, mock_safe_load, mock_load_config
    ):
        mock_load_config.return_value = "mocked_config_file_content"
        mock_safe_load.return_value = {"config": {"configVersion": "1.0"}}
        mock_exists.return_value = True
        mock_deep_traverse.return_value = {"mocked": "resolved_config"}
        mock_validate.return_value = True

        config_file = "config_file.yaml"

        result = validate_config_schema(config_file)

        self.assertTrue(result)
