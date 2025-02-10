import os
import unittest
from unittest.mock import patch

from rapidast import deep_traverse_and_replace_with_var_content


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
