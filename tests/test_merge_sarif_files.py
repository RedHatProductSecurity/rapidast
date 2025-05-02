import json
import logging
import os
import unittest
from unittest.mock import mock_open
from unittest.mock import patch

from rapidast import merge_sarif_files


class TestMergeSarifFiles(unittest.TestCase):
    def setUp(self):
        self.scanner_results = {"scanner1": {"duration": 1.2}, "scanner2": {"duration": 0.8}}
        self.output_file = "merged_test.sarif.json"
        self.fixtures_dir = os.path.join(os.path.dirname(__file__), "fixtures")

        os.makedirs(self.fixtures_dir, exist_ok=True)

    def tearDown(self):
        if os.path.exists(self.output_file):
            os.remove(self.output_file)
        # We might not need to remove the fixtures directory

    def _load_fixture_json(self, filename):
        filepath = os.path.join(self.fixtures_dir, filename)
        with open(filepath, "r") as f:
            logging.warning(filepath)
            return json.load(f)

    @patch("os.listdir")
    @patch("json.dump")
    @patch("logging.warning")
    def test_no_sarif_files(self, mock_log_warning, mock_dump, mock_listdir):
        mock_listdir.return_value = []
        merge_sarif_files(self.fixtures_dir, self.scanner_results, self.output_file)
        args, _ = mock_dump.call_args
        self.assertEqual(args[0]["properties"], self.scanner_results)
        self.assertEqual(len(args[0]["runs"]), 0)
        self.assertEqual(args[0]["version"], "2.1.0")
        mock_log_warning.assert_called_once()

    @patch("os.listdir")
    @patch("json.dump")
    def test_merge_sarif_files(self, mock_dump, mock_listdir):
        mock_listdir.return_value = ["zap-report.sarif.json", "garak-report.sarif"]
        zap_log = self._load_fixture_json("zap-report.sarif.json")
        garak_log = self._load_fixture_json("garak-report.sarif")
        merge_sarif_files(self.fixtures_dir, self.scanner_results, self.output_file)
        args, _ = mock_dump.call_args
        self.assertEqual(len(args[0]["runs"]), 2)
        self.assertEqual(args[0]["runs"][0], zap_log["runs"][0])
        self.assertEqual(args[0]["runs"][1], garak_log["runs"][0])
        self.assertEqual(args[0]["properties"], self.scanner_results)

    @patch("os.listdir")
    @patch("json.dump")
    @patch("logging.error")
    def test_error_reading_sarif_file(self, mock_log_error, mock_dump, mock_listdir):
        mock_listdir.return_value = ["bad_report.sarif"]
        merge_sarif_files(self.fixtures_dir, self.scanner_results, self.output_file)
        args, _ = mock_dump.call_args
        self.assertEqual(args[0]["properties"], self.scanner_results)
        self.assertEqual(len(args[0]["runs"]), 0)
        self.assertEqual(args[0]["version"], "2.1.0")
        mock_log_error.assert_called_once()
