import unittest
from unittest.mock import MagicMock, patch
import rapidast
import urllib  # pylint: disable=unused-import


class TestLoadConfigFile(unittest.TestCase):
    @patch('urllib.request.urlopen')
    def test_load_config_file_from_url(self, mock_urlopen):
        response = MagicMock()
        response.getcode.return_value = 200
        response.read.return_value = "config: 3"
        mock_urlopen.return_value = response
        result = rapidast.load_config_file("https://location/config.yaml")
        assert result is response

    @patch('builtins.open')
    def test_load_config_file_from_local_file(self, mock_open):
        response = MagicMock()
        mock_open.return_value = response
        result = rapidast.load_config_file("./config/config.yaml")
        assert result is response
