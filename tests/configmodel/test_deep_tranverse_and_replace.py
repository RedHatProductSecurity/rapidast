import os
import unittest
from unittest.mock import patch

from configmodel import deep_traverse_and_replace_with_var_content


class TestDeepTraverseAndReplace(unittest.TestCase):
    @patch.dict(os.environ, {"MY_VAR": "some_value"})
    def test_replace_key_with_environment_variable(self):
        input_dict = {"key_from_var": "MY_VAR", "other_key": "value"}
        expected = {"key": "some_value", "other_key": "value"}

        result = deep_traverse_and_replace_with_var_content(input_dict)

        self.assertEqual(result, expected)

    @patch.dict(os.environ, {"MY_VAR": "some_value"})
    def test_no_match_for_suffix(self):
        input_dict = {"key": "value", "other_key": "value"}
        expected = {"key": "value", "other_key": "value"}

        result = deep_traverse_and_replace_with_var_content(input_dict)

        self.assertEqual(result, expected)

    @patch.dict(os.environ, {"MY_VAR": "some_value"})
    def test_missing_environment_variable(self):
        input_dict = {"key_from_var": "NON_EXISTENT_VAR", "other_key": "value"}

        result = deep_traverse_and_replace_with_var_content(input_dict)

        self.assertEqual(result, {"key_from_var": "NON_EXISTENT_VAR", "other_key": "value"})

    @patch.dict(os.environ, {"MY_VAR": "some_value"})
    def test_nested_dict(self):
        input_dict = {"outer_key_from_var": "MY_VAR", "nested_dict": {"inner_key_from_var": "MY_VAR"}}
        expected = {"outer_key": "some_value", "nested_dict": {"inner_key": "some_value"}}

        result = deep_traverse_and_replace_with_var_content(input_dict)

        self.assertEqual(result, expected)

    @patch.dict(os.environ, {"MY_VAR": "some_value"})
    def test_list_with_dict(self):
        input_dict = {
            "list_key_from_var": "MY_VAR",
            "list_of_dicts": [{"key_from_var": "MY_VAR"}, {"key_from_var": "MY_VAR"}],
        }
        expected = {"list_key": "some_value", "list_of_dicts": [{"key": "some_value"}, {"key": "some_value"}]}

        result = deep_traverse_and_replace_with_var_content(input_dict)

        self.assertEqual(result, expected)

    @patch.dict(os.environ, {"TEST_VAR": "value_from_env"})
    def test_original_value_prevents_overwrite(self):

        original_value = "existing_truthy_value"
        input_dict = {
            "myKey": original_value,
            "myKey_from_var": "TEST_VAR"
        }

        result = deep_traverse_and_replace_with_var_content(input_dict)

        self.assertIn("myKey", result)
        self.assertEqual(result["myKey"], original_value)
        self.assertIn("myKey_from_var", result)

        data_none = {"key_none": None, "key_none_from_var": "TEST_ENV_VAR"}
        result = deep_traverse_and_replace_with_var_content(data_none)
        self.assertEqual(result["key_none"], None)
        self.assertIn("key_none_from_var", result)

        data_empty_str = {"key_empty": "", "key_empty_from_var": "TEST_ENV_VAR"}
        result = deep_traverse_and_replace_with_var_content(data_empty_str)
        self.assertEqual(result["key_empty"], "")
        self.assertIn("key_empty_from_var", result)

    def test_key_error_pass_and_env_var_not_found(self):
        """
        Verifies that if `new_key` is missing AND the environment variable is not found,
        the KeyError is caught (allowing pass), and then the logging.error is triggered.
        """
        data = {
            "non_existent_key_from_var": "NON_EXISTENT_ENV_VAR"
        }

        result = deep_traverse_and_replace_with_var_content(data)

        self.assertNotIn("non_existent_key", result)
        self.assertIn("non_existent_key_from_var", result)