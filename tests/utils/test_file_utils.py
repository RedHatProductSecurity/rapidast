import unittest

from utils.file_utils import sanitize_filename


class TestSanitizeFilename(unittest.TestCase):
    def test_with_alpha_only(self):
        self.assertEqual(sanitize_filename("MyApp"), "MyApp")

    def test_with_alphanumric_dots_hyphens_underscores(self):
        self.assertEqual(sanitize_filename("My_App-1.0"), "My_App-1.0")

    def test_with_spaces(self):
        self.assertEqual(sanitize_filename("MyApp 1.0"), "MyApp_1.0")

    def test_with_special_characters(self):
        self.assertEqual(sanitize_filename("MyApp: 1.0@1234abcd"), "MyApp_1.0_1234abcd")

    def test_with_slashes(self):
        self.assertEqual(sanitize_filename("MyApp/version/1.0"), "MyApp_version_1.0")

    def test_with_unicode(self):
        self.assertEqual(sanitize_filename("MyApp 测试 名称"), "MyApp_")

    def test_only_special_characters(self):
        self.assertEqual(sanitize_filename("@#$%^&*()"), "_")

    def test_empty_string(self):
        self.assertEqual(sanitize_filename(""), "")
