import configmodel
import rapidast

import requests

from scanners.nessus.nessus import Nessus
from unittest.mock import Mock, patch


class TestNessus:
    @patch("requests.Session.request")
    @patch("py_nessus_pro.py_nessus_pro.BeautifulSoup")  # patch where imported
    @patch("py_nessus_pro.py_nessus_pro.webdriver")  # patch where imported
    def test_setup_nessus(self, mock_driver, mock_bs4, mock_get):
        # All this mocking is for PyNessusPro.__init__() which attempts to connect to Nessus
        mock_soup = Mock()
        mock_soup.find_all.return_value = [{"src": "foo"}]
        mock_bs4.return_value = mock_soup
        mock_get.return_value = Mock(spec=requests.Response)
        mock_get.return_value.status_code = 200
        mock_get.return_value.text = '{"token": "foo", "folders": []}'

        config_data = rapidast.load_config("config/config-template-nessus.yaml")
        config = configmodel.RapidastConfigModel(config_data)
        test_nessus = Nessus(config=config)
        assert test_nessus is not None
        assert test_nessus.nessus_client is not None
