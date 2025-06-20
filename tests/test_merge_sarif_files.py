import json
import os
import tempfile
import unittest
from unittest.mock import patch

from rapidast import collect_sarif_files
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

    def _load_fixture_json(self, filename):
        filepath = os.path.join(self.fixtures_dir, filename)
        with open(filepath, "r", encoding="utf8") as f:
            return json.load(f)

    def test_merge_sarif_files(self):
        zap_log = self._load_fixture_json("zap-report.sarif.json")
        garak_log = self._load_fixture_json("garak-report.sarif")

        with tempfile.NamedTemporaryFile(mode="w+", delete=False, suffix=".json") as tmp_file:
            output_file = tmp_file.name

        try:
            merge_sarif_files(self.fixtures_dir, self.scanner_results, self.output_file)

            with open(self.output_file, "r", encoding="utf8") as f:
                merged = json.load(f)

            self.assertEqual(len(merged["runs"]), 2)
            self.assertEqual(merged["runs"][0], garak_log["runs"][0])
            self.assertEqual(merged["runs"][1], zap_log["runs"][0])
            self.assertEqual(merged["properties"], self.scanner_results)
        finally:
            os.remove(output_file)

    @patch("rapidast.collect_sarif_files")
    @patch("json.dump")
    @patch("logging.error")
    def test_error_reading_sarif_file(self, mock_log_error, mock_dump, mock_collect_sarif_files):
        mock_collect_sarif_files.return_value = ["bad_report.sarif"]
        merge_sarif_files(self.fixtures_dir, self.scanner_results, self.output_file)
        args, _ = mock_dump.call_args
        self.assertEqual(args[0]["properties"], self.scanner_results)
        self.assertEqual(len(args[0]["runs"]), 0)
        self.assertEqual(args[0]["version"], "2.1.0")
        mock_log_error.assert_called_once()


class TestCollectSarifFiles(unittest.TestCase):
    def test_collect_sarif_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            os.makedirs(os.path.join(tmpdir, "subdir"), exist_ok=True)
            os.makedirs(os.path.join(tmpdir, "subdir1", "subdir2"), exist_ok=True)
            with open(os.path.join(tmpdir, "file1.sarif"), "w") as f:
                f.write("{}")
            with open(os.path.join(tmpdir, "subdir", "file2.sarif.json"), "w") as f:
                f.write("{}")
            with open(os.path.join(tmpdir, "file3.txt"), "w") as f:
                f.write("not a sarif file")
            with open(os.path.join(tmpdir, "subdir1", "subdir2", "file4.sarif"), "w") as f:
                f.write("{}")

            sarif_files = collect_sarif_files(tmpdir)

            expected_files = [
                os.path.join(tmpdir, "file1.sarif"),
                os.path.join(tmpdir, "subdir", "file2.sarif.json"),
                os.path.join(tmpdir, "subdir1", "subdir2", "file4.sarif"),
            ]
            self.assertEqual(sorted(sarif_files), sorted(expected_files))

    @patch("logging.warning")
    def test_no_sarif_files(self, mock_log_warning):
        with tempfile.TemporaryDirectory() as tmpdir:
            sarif_files = collect_sarif_files(tmpdir)
            self.assertEqual([], sarif_files)

        mock_log_warning.assert_called_once()
